use crate::allowance::{AllowanceBinding, InvestigationWork};
use crate::findings::test_support::ReviewedFindingFixture;
use crate::findings::{ReviewDecisionVerdict, TriageOutcome};
use crate::modules::{AllowanceCategory, ModuleMaturity};
use crate::runtime::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, RuntimeCost, RuntimeCostReport,
    TriageRequest,
};
use crate::{ModuleRegistry, ToolExecutionContext, V2Config};
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct PatternRuntime {
    binding: Option<AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    response: Value,
}

impl AgentRuntime for PatternRuntime {
    fn allowance_binding(&self) -> Option<&AllowanceBinding> {
        self.binding.as_ref()
    }
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
        let binding = self.binding.as_ref().unwrap();
        assert_eq!(binding.work().work, InvestigationWork::Learning);
        let reservation = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reservation, RuntimeCostReport::known(RuntimeCost::ZERO))?;
        Ok(AgentQueryResponse {
            structured: Some(self.response.clone()),
            cost_usd_reported: true,
            ..Default::default()
        })
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        anyhow::bail!("Owned source-pattern test forbids triage")
    }
}

fn pattern() -> Value {
    json!({"source":"Owned input metadata","sink":"Owned output metadata",
        "missingGuard":"Owned scope condition","description":"Labeled owned draft. No defect is claimed.",
        "languages":["rust"],"keywords":["owned-marker"]})
}

fn context<'a>(
    fixture: &'a ReviewedFindingFixture,
    config: &'a V2Config,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(&fixture.workspace),
        findings_store: Some(&fixture.store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn approve(registry: &ModuleRegistry, ctx: &ToolExecutionContext<'_>, calls: u64, protected: u64) {
    let prepared = registry.prepare_dispatch_input("campaign:approve-allowance",json!({
        "investigationId":"owned-pattern","expectedRevision":0,"model":"openai:gpt-4.1",
        "maxProviderCalls":calls,"protectedReviewCalls":protected,"reason":"Owned intercepted-unit fixture"}),ctx,None)
        .unwrap().authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, ctx, None)
        .unwrap();
}

fn dispatch(ctx: &ToolExecutionContext<'_>, runtime: &PatternRuntime) -> Result<Value> {
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry.prepare_dispatch_input("variant:lift-pattern",json!({
        "fingerprint":"F-0001","allowanceRef":{"schemaVersion":1,"investigationId":"owned-pattern","revision":1,"workId":"owned-draft"}}),ctx,None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, ctx, Some(runtime))
}

#[test]
fn source_pattern_drafts_are_experimental_learning_not_scan_progress() {
    let registry = ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("variant:lift-pattern").unwrap();
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
    assert_eq!(tool.allowance_category, Some(AllowanceCategory::Learning));
    assert!(!tool.phase_result);
    assert!(!registry.tool_is_discoverable(&tool.name));
    assert!(tool.description.contains("findings:lesson-generate"));
    let prepared = registry
        .prepare_tool_input(
            "variant:lift-pattern",
            json!({"fingerprint":"owned","thinking_level":"low"}),
            None,
        )
        .unwrap();
    assert_eq!(prepared["thinkingLevel"], "low");
}

#[test]
fn prepared_generation_preserves_subject_history_and_returns_only_an_unaccepted_draft() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_human_decision(ReviewDecisionVerdict::Confirmed);
    let before = fixture.store.list_all_review_decisions().unwrap();
    let config = V2Config {
        model: Some("openai:gpt-4.1".into()),
        ..Default::default()
    };
    let ctx = context(&fixture, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    approve(&registry, &ctx, 3, 1);
    let runtime = PatternRuntime {
        binding: None,
        requests: Arc::new(Mutex::new(vec![])),
        response: pattern(),
    };
    let result = dispatch(&ctx, &runtime).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["signature"], pattern());
    assert_eq!(result["data"]["accepted"], false);
    assert_eq!(result["data"]["contextActivated"], false);
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(runtime.requests.lock().unwrap()[0].thinking_level, None);
    assert!(runtime.requests.lock().unwrap()[0]
        .prompt
        .contains("Author: human"));
    assert_eq!(fixture.store.list_all_review_decisions().unwrap(), before);
    assert_eq!(fixture.store.list_all_findings().unwrap().len(), 1);
}

#[test]
fn invalid_draft_output_cannot_be_reported_as_completed() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_human_decision(ReviewDecisionVerdict::Confirmed);
    let config = V2Config {
        model: Some("openai:gpt-4.1".into()),
        ..Default::default()
    };
    let ctx = context(&fixture, &config);
    approve(&ModuleRegistry::with_v2_builtins(), &ctx, 3, 1);
    let runtime = PatternRuntime {
        binding: None,
        requests: Arc::new(Mutex::new(vec![])),
        response: json!({}),
    };
    let error = dispatch(&ctx, &runtime).unwrap_err();
    assert!(format!("{error:#}").contains("after one repair"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 2);
    assert_eq!(fixture.store.list_all_findings().unwrap().len(), 1);
}

#[test]
fn drafting_cannot_borrow_protected_review_calls() {
    let fixture = ReviewedFindingFixture::new();
    fixture.record_human_decision(ReviewDecisionVerdict::Confirmed);
    let config = V2Config {
        model: Some("openai:gpt-4.1".into()),
        ..Default::default()
    };
    let ctx = context(&fixture, &config);
    approve(&ModuleRegistry::with_v2_builtins(), &ctx, 1, 1);
    let runtime = PatternRuntime {
        binding: None,
        requests: Arc::new(Mutex::new(vec![])),
        response: pattern(),
    };
    let error = dispatch(&ctx, &runtime).unwrap_err();
    assert!(format!("{error:#}").contains("allowance"));
    assert!(runtime.requests.lock().unwrap().is_empty());
}
