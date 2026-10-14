use super::*;
use crate::allowance::AllowanceBinding;
use crate::runtime::{AgentQueryRequest, AgentQueryResponse};
use std::sync::{Arc, Mutex};

const TOOL: &str = "module-recommender:recommend";
const MODEL: &str = "openai-codex:gpt-5.5";

struct Fixture {
    root: tempfile::TempDir,
    workspace: crate::WorkspaceTarget,
    config: crate::V2Config,
    registry: ModuleRegistry,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("owned.rs"),
            "// Owned metadata fixture. Never executed.\n",
        )
        .unwrap();
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        Self {
            root,
            workspace,
            config: crate::V2Config {
                model: Some(MODEL.into()),
                ..Default::default()
            },
            registry: ModuleRegistry::with_v2_builtins_without_optional_adapters(),
        }
    }
    fn ctx(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }
    fn dispatch(
        &self,
        tool: &str,
        input: Value,
        runtime: Option<&dyn AgentRuntime>,
        approve: bool,
    ) -> Result<Value> {
        let ctx = self.ctx();
        let mut prepared = self
            .registry
            .prepare_dispatch_input(tool, input, &ctx, None)?;
        if approve {
            prepared = prepared.authorize_explicit_headless();
        }
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, runtime)
    }
    fn approve(&self) {
        self.dispatch(
            "campaign:approve-allowance",
            json!({"investigationId":"ranking",
            "expectedRevision":0,"model":MODEL,"maxProviderCalls":2,"protectedReviewCalls":1,
            "reason":"Owned intercepted single ranking test"}),
            None,
            true,
        )
        .unwrap();
    }
    fn dispatch_named(&self, run_id: &str) {
        let trace = crate::run_artifacts::TraceHandle::jsonl(self.root.path(), run_id);
        let mut ctx = self.ctx();
        ctx.trace = Some(&trace);
        let prepared = self.registry.prepare_dispatch_input(TOOL, json!({}), &ctx, None).unwrap();
        self.registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None).unwrap();
    }
    fn model_input(&self) -> Value {
        json!({"useModelRanking":true,"allowanceRef":{"schemaVersion":1,
            "investigationId":"ranking","revision":1,"workId":"one-ranking"}})
    }
    fn snapshot(&self) -> crate::allowance::AllowanceSnapshot {
        crate::SpendLimiter::open(self.workspace.findings_db_path())
            .unwrap()
            .allowance_snapshot("ranking")
            .unwrap()
    }
}

#[derive(Clone)]
struct OfflineRuntime {
    binding: Option<AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    text: &'static str,
}
impl OfflineRuntime {
    fn new(text: &'static str) -> Self {
        Self {
            binding: None,
            requests: Default::default(),
            text,
        }
    }
}
impl AgentRuntime for OfflineRuntime {
    fn with_allowance_binding(
        &self,
        binding: AllowanceBinding,
    ) -> Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(Self {
            binding: Some(binding),
            ..self.clone()
        }))
    }
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let binding = self
            .binding
            .as_ref()
            .context("Missing approved runtime binding")?;
        let reserved = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        let response = AgentQueryResponse {
            text: self.text.into(),
            cost_usd: 0.4,
            cost_usd_reported: true,
            ..Default::default()
        };
        binding.settle(reserved, response.checked_cost_report()?)?;
        Ok(response)
    }
    fn triage_finding_blocking(&self, _: crate::TriageRequest) -> Result<crate::TriageOutcome> {
        anyhow::bail!("No triage in recommendation audit")
    }
}

#[test]
fn recommendation_descriptor_is_operational_input_aware_and_scope_accounted() {
    let f = Fixture::new();
    let tool = f.registry.resolve_tool(TOOL).unwrap();
    assert_eq!(tool.phase, ToolPhase::Operate);
    assert_eq!(tool.runtime_requirement, RuntimeRequirement::InputAware);
    assert!(!tool.phase_result);
    assert_eq!(tool.allowance_category, Some(AllowanceCategory::Scope));
    let prepared = f
        .registry
        .prepare_tool_input(TOOL, json!({}), None)
        .unwrap();
    assert_eq!(prepared["useModelRanking"], false);
    assert!(!f.registry.tool_wants_runtime(TOOL, &prepared, &f.config));
}

#[test]
fn default_recommendations_do_not_require_model_credentials_or_start_discovery() {
    let f = Fixture::new();
    let result = f.dispatch(TOOL, json!({}), None, false).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["rankingMode"], "deterministic");
    assert!(result["data"]["model"].is_null());
    assert_eq!(result["data"]["costUsdExact"], true);
    for row in result["data"]["recommendations"].as_array().unwrap() {
        let descriptor = f
            .registry
            .resolve_tool(row["tool"].as_str().unwrap())
            .unwrap();
        assert!(!matches!(
            descriptor.phase,
            ToolPhase::Prove | ToolPhase::Fix
        ));
    }
    assert!(!f.root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn explicit_ranking_requires_allowance_before_runtime_construction() {
    let f = Fixture::new();
    let error = f
        .registry
        .prepare_tool_input(TOOL, json!({"modelRanking":true}), None)
        .unwrap_err();
    assert!(error.to_string().contains("approved allowanceRef"));
}

#[test]
fn ranking_reserves_one_scope_call_preserves_review_and_refuses_extra_work() {
    let f = Fixture::new();
    f.approve();
    let runtime = OfflineRuntime::new(
        r#"[{"tool":"context:build","priority":"high","reason":"Inspect existing source facts"}]"#,
    );
    let result = f
        .dispatch(TOOL, f.model_input(), Some(&runtime), false)
        .unwrap();
    assert_eq!(result["data"]["rankingMode"], "model");
    assert_eq!(result["data"]["model"], MODEL);
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    let snapshot = f.snapshot();
    assert_eq!(snapshot.committed_calls, 1);
    assert_eq!(snapshot.protected_review_remaining(), 1);
    assert_eq!(snapshot.cost.exact_usd(), Some(0.4));
    assert!(f
        .dispatch(TOOL, f.model_input(), Some(&runtime), false)
        .is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn malformed_model_output_keeps_spending_and_does_not_create_fallback_proposals() {
    let f = Fixture::new();
    f.approve();
    let runtime = OfflineRuntime::new("invalid");
    let error = f
        .dispatch(TOOL, f.model_input(), Some(&runtime), false)
        .unwrap_err();
    assert!(format!("{error:#}").contains("no repair request"));
    assert_eq!(f.snapshot().committed_calls, 1);
    assert_eq!(f.snapshot().cost.exact_usd(), Some(0.4));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(crate::strategy::load_strategy_queue(&f.workspace)
        .unwrap()
        .is_empty());
}

#[test]
fn truncated_inventory_recommendations_are_partial_and_disclosed() {
    let f = Fixture::new();
    std::fs::write(
        f.root.path().join("large.rs"),
        "// owned bounded metadata\n".repeat(20000),
    )
    .unwrap();
    let result = f.dispatch(TOOL, json!({}), None, false).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["inventoryCoverage"]["status"], "partial");
    assert_eq!(
        result["data"]["inventoryCoverage"]["completeRepositoryCoverage"],
        false
    );
    assert!(
        result["data"]["inventoryCoverage"]["truncatedFiles"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
fn regenerated_recommendations_preserve_review_history_and_require_new_approval() {
    let f = Fixture::new();
    f.dispatch(TOOL, json!({}), None, false).unwrap();
    let mut original = crate::strategy::load_strategy_queue(&f.workspace).unwrap();
    assert!(!original.is_empty());
    original[0].status = crate::StrategyProposalStatus::Approved;
    original[0].approved_cost_usd = Some(0.3);
    original[0].corrected_strategy = Some("retained operator correction".into());
    original[0].result_run_id = Some("owned-history".into());
    original[0].actual_cost_usd = Some(0.2);
    original[0].findings_count = Some(2);
    crate::strategy::save_strategy_queue(&f.workspace, &original).unwrap();
    std::fs::write(f.root.path().join("other.rs"), "// Owned changed source.\n").unwrap();
    f.dispatch(TOOL, json!({}), None, false).unwrap();
    let queue = crate::strategy::load_strategy_queue(&f.workspace).unwrap();
    assert_eq!(&queue[..original.len()], original.as_slice());
    assert!(queue.len() > original.len());
    for draft in &queue[original.len()..] {
        assert_eq!(draft.status, crate::StrategyProposalStatus::Proposed);
        assert_eq!(draft.approved_cost_usd, None);
        assert_eq!(draft.actual_cost_usd, None);
        assert_eq!(draft.result_run_id, None);
        assert!(!original.iter().any(|old| old.id == draft.id));
    }
    assert_eq!(queue.iter().filter(|p| p.status == crate::StrategyProposalStatus::Approved).count(), 1);
}

#[test]
fn generation_artifact_contains_only_new_drafts_with_reviewed_workspace_corrections() {
    let f = Fixture::new();
    f.dispatch_named("owned-generation-one");
    let correction = crate::StrategyCorrection::new(crate::StrategyPhase::Review,
        Some("review-context-build".into()), "run context:build", "operator metadata preference",
        crate::StrategyCorrectionScope::Workspace, None, "owned review", "operator");
    crate::record_strategy_correction(&f.workspace, &correction).unwrap();
    let original = crate::load_strategy_queue(&f.workspace).unwrap();
    f.dispatch_named("owned-generation-two");
    let current = crate::load_strategy_queue(&f.workspace).unwrap();
    assert_eq!(&current[..original.len()], original.as_slice());
    let path = crate::run_artifacts::run_artifact_path(f.root.path(), "owned-generation-two", "strategy.json");
    let artifact: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let drafts = artifact["strategyProposals"].as_array().unwrap();
    assert!(!drafts.is_empty());
    assert!(drafts.iter().all(|p| p["status"] == "proposed" && p["sourceRunId"] == "owned-generation-two"));
    let context = drafts.iter().find(|p| p["tool"] == "context:build").unwrap();
    assert_eq!(context["correctedStrategy"], "operator metadata preference");
    assert_eq!(context["appliedCorrections"][0]["id"], correction.id);
    assert_ne!(context["id"], "review-context-build");
}
