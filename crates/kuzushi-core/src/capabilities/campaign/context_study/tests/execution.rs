use super::*;
use crate::{
    allowance::AllowanceBinding,
    runtime::{
        AgentQueryRequest, AgentQueryResponse, AgentRuntime, RuntimeCostReport, TriageRequest,
    },
    TriageOutcome,
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct OfflineContextRuntime {
    binding: Option<AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
}

impl AgentRuntime for OfflineContextRuntime {
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
            .context("test request has no approved allowance")?;
        let reservation = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reservation, RuntimeCostReport::UNAVAILABLE)?;
        Ok(AgentQueryResponse {
            structured: Some(document()),
            ..Default::default()
        })
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        unreachable!()
    }
}

fn document() -> Value {
    json!({"version":"2.0","title":"Offline generated context",
        "dfd":{"nodes":[{"id":"app","type":"process","name":"Command line application","description":"Prints a greeting","trustZone":"internal","evidenceAnchors":[{"filePath":"main.rs","startLine":1}]},{"id":"terminal","type":"external-entity","name":"Terminal","description":"Receives standard output","trustZone":"external"}],"flows":[{"id":"stdout","sourceId":"app","targetId":"terminal","description":"Greeting on standard output","trustBoundaryIds":[]}],"trustBoundaries":[]},
        "threats":[],"summary":{"total":0,"bySeverity":{},"byCategory":{}},"openQuestions":["Which callers supply the input?"]})
}

#[test]
fn context_study_executes_real_generator_with_mock_provider_and_retains_spending_for_scans() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "fn main() { println!(\"hello\"); }\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "context-run");
    let mut ctx = context(&workspace, &config);
    ctx.trace = Some(&trace);
    draft(&registry, &ctx, json!({})).unwrap();
    let receipt = load_context_study(root.path(), "context-draft").unwrap();
    approve(&registry, &ctx, approval(&receipt)).unwrap();
    let allowance = receipt.load_allowance(root.path()).unwrap().unwrap();
    let input = receipt.bound_input(&allowance).unwrap();
    let runtime = OfflineContextRuntime::default();
    let prepared = registry
        .prepare_dispatch_input(TOOL, input.clone(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    let reference: crate::ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    assert!(
        crate::capabilities::threat_model::load_exact_threat_model(root.path(), &reference).is_ok()
    );
    assert!(
        crate::capabilities::threat_model::load_active_threat_model(root.path())
            .unwrap()
            .is_none()
    );
    write_json_atomic(
        &campaign_queue_path(root.path(), "context-draft"),
        &json!({"jobs":{"context-001":{"state":"completed","runId":"context-run"}}}),
    )
    .unwrap();
    assert_eq!(
        receipt.generated_context(root.path()).unwrap(),
        Some(reference.clone())
    );
    let trace2 = crate::run_artifacts::TraceHandle::jsonl(root.path(), "unapproved-context-retry");
    ctx.trace = Some(&trace2);
    let prepared = registry
        .prepare_dispatch_input(TOOL, input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .unwrap_err();
    assert!(error.to_string().contains("attempt limit"), "{error:#}");
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    approve_scan_after_context(&registry, &ctx, reference);
}

fn approve_scan_after_context(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    reference: crate::ThreatModelRef,
) {
    let scan = registry
        .execute_tool(
            "campaign:study",
            json!({"campaignId":"scan-after-context","investigationId":"investigation",
        "scanInput":{"tasks":["secret-scan"],"taskMode":"manual","threatModelRef":reference}}),
            ctx,
        )
        .unwrap();
    let input = json!({"investigationId":"investigation","expectedRevision":1,"model":MODEL,
        "maxProviderCalls":5,"protectedReviewCalls":2,"reason":"Continue the same investigation with three finite scans",
        "campaignId":"scan-after-context","campaignPlanSha256":scan["data"]["planSha256"],"campaignJobs":3,"maxJobAttempts":1});
    let result = approve(registry, ctx, input).unwrap();
    let allowance = &result["data"]["allowance"];
    assert_eq!(allowance["committedCalls"], 1);
    assert_eq!(allowance["unresolvedCalls"], 0);
    let snapshot: crate::allowance::AllowanceSnapshot =
        serde_json::from_value(allowance.clone()).unwrap();
    assert!(!snapshot.cost.is_complete());
    assert_eq!(allowance["revision"], 2);
    assert_eq!(allowance["workPlan"]["jobs"].as_array().unwrap().len(), 3);
}
