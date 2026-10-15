use super::*;
use crate::allowance::AllowanceBinding;
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct ProposalRuntime {
    binding: Option<AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    response: AgentQueryResponse,
}

impl AgentRuntime for ProposalRuntime {
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
        let binding = self.binding.as_ref().context("missing approved binding")?;
        let reservation = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reservation, self.response.checked_cost_report()?)?;
        Ok(self.response.clone())
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<crate::TriageOutcome> {
        unreachable!()
    }
}

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: V2Config,
    registry: ModuleRegistry,
    receipt: ContextStudyReceipt,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "// Inert owned fixture. Never executed.\nfn main() {}\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    registry.execute_tool("campaign:context-study", json!({"campaignId":"context-draft","investigationId":"investigation","generationTool":"planner:propose","contextInput":{"goal":"Inspect this owned repository","phase":"scan","thinkingLevel":"low"}}), &context(&workspace, &config)).unwrap();
    let receipt = load_context_study(root.path(), "context-draft").unwrap();
    Fixture {
        root,
        workspace,
        config,
        registry,
        receipt,
    }
}

fn response() -> AgentQueryResponse {
    AgentQueryResponse {
        structured: Some(
            json!({"summary":"Review the declared scanner options", "changes":[{"kind":"note","text":"Choose scanner scope before execution"}],"unsupported":["Which scope should be inspected?"]}),
        ),
        ..Default::default()
    }
}

fn execute(f: &Fixture, runtime: &ProposalRuntime, input: Value) -> Result<Value> {
    let trace = crate::run_artifacts::TraceHandle::jsonl(f.root.path(), "proposal-run");
    let mut ctx = context(&f.workspace, &f.config);
    ctx.trace = Some(&trace);
    let record = crate::run_artifacts::ToolRunRecord::new(
        f.root.path(),
        "proposal-run",
        "tool",
        "planner:propose",
    );
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &input,
        Some(MODEL.into()),
        None,
        vec![],
    )?;
    let prepared = f
        .registry
        .prepare_dispatch_input("planner:propose", input, &ctx, None)?
        .authorize_explicit_headless();
    let observed =
        f.registry
            .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, Some(runtime))?;
    let result = observed.execution?;
    crate::run_artifacts::try_record_tool_run_complete_settled(
        record,
        &result,
        &trace.run_observation().context("missing observation")?,
        observed.completion,
    )?;
    write_json_atomic(
        &campaign_queue_path(f.root.path(), "context-draft"),
        &json!({"jobs":{"context-001":{"state":result["status"],"runId":"proposal-run"}}}),
    )?;
    Ok(result)
}

fn approved_input(f: &Fixture) -> Value {
    approve(
        &f.registry,
        &context(&f.workspace, &f.config),
        approval(&f.receipt),
    )
    .unwrap();
    f.receipt
        .bound_input(&f.receipt.load_allowance(f.root.path()).unwrap().unwrap())
        .unwrap()
}

#[test]
fn planner_draft_and_missing_approval_make_no_provider_requests() {
    let f = fixture();
    assert_eq!(f.receipt.job_count(), 1);
    assert!(f.receipt.preparation_jobs.is_empty());
    assert!(f.receipt.input["proposalConfigSha256"].is_string());
    let runtime = ProposalRuntime::default();
    assert!(execute(&f, &runtime, f.receipt.input.clone()).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert!(f.receipt.load_allowance(f.root.path()).unwrap().is_none());
}

#[test]
fn planner_shared_dispatch_is_single_tool_free_and_restart_readable() {
    let f = fixture();
    let input = approved_input(&f);
    let runtime = ProposalRuntime {
        response: response(),
        ..Default::default()
    };
    let output = execute(&f, &runtime, input).unwrap();
    assert_eq!(output["status"], "completed", "{output}");
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0]
            .runtime_options
            .as_ref()
            .unwrap()
            .max_model_turns,
        Some(1)
    );
    assert!(requests[0].tool_policy.tools.is_empty());
    assert!(!requests[0].tool_policy.mcps);
    assert_eq!(requests[0].model, MODEL);
    let restored = load_context_study(f.root.path(), "context-draft").unwrap();
    assert!(restored.workflow_proposal(f.root.path()).unwrap().is_some());
    restored
        .validate_workflow_proposal_actions(f.root.path(), &f.registry)
        .unwrap();
    assert_eq!(
        restored
            .load_allowance(f.root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        1
    );
    assert_eq!(
        super::super::super::snapshot::load_campaign_snapshot(f.root.path(), "context-draft")
            .unwrap()
            .jobs
            .len(),
        1
    );
}

#[test]
fn planner_malformed_response_keeps_raw_cost_and_makes_no_repair_request() {
    let f = fixture();
    let input = approved_input(&f);
    let runtime = ProposalRuntime {
        response: AgentQueryResponse {
            text: "Malformed labeled response".into(),
            cost_usd: 0.02,
            cost_usd_reported: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let output = execute(&f, &runtime, input).unwrap();
    assert_eq!(output["status"], "partial");
    assert_eq!(output["data"]["rawProposal"], "Malformed labeled response");
    assert!(output["data"]["costReport"].is_object());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(f.receipt.workflow_proposal(f.root.path()).is_err());
    assert_eq!(
        f.receipt
            .load_allowance(f.root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        1
    );
}

#[test]
fn planner_excessive_response_discloses_omission_without_another_request() {
    let f = fixture();
    let input = approved_input(&f);
    let runtime = ProposalRuntime {
        response: AgentQueryResponse {
            text: "x".repeat(128 * 1024 + 1),
            ..Default::default()
        },
        ..Default::default()
    };
    let output = execute(&f, &runtime, input).unwrap();
    assert_eq!(output["status"], "partial");
    assert_eq!(output["data"]["rawProposal"]["omitted"], true);
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn planner_source_drift_blocks_approval_and_actions_but_preserves_history() {
    let f = fixture();
    let input = approved_input(&f);
    execute(
        &f,
        &ProposalRuntime {
            response: response(),
            ..Default::default()
        },
        input,
    )
    .unwrap();
    std::fs::write(
        f.root.path().join("main.rs"),
        "// Owned changed source. Never executed.\nfn changed() {}\n",
    )
    .unwrap();
    assert!(f
        .receipt
        .workflow_proposal(f.root.path())
        .unwrap()
        .is_some());
    assert!(f
        .receipt
        .validate_workflow_proposal_actions(f.root.path(), &f.registry)
        .is_err());
}

#[test]
fn planner_invalid_fingerprint_is_refused_before_reserving_a_call() {
    let f = fixture();
    let mut input = approved_input(&f);
    input["proposalConfigSha256"] = json!("changed");
    let runtime = ProposalRuntime::default();
    assert!(execute(&f, &runtime, input).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(
        f.receipt
            .load_allowance(f.root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        0
    );
}
