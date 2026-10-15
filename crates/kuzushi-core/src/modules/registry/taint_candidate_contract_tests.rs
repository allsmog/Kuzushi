use crate::allowance::AllowanceBinding;
use crate::findings::{FindingStore, TriageOutcome};
use crate::modules::{ModuleMaturity, RuntimeRequirement, ToolPhase};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use anyhow::Result;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Default)]
struct NoQueries {
    calls: Arc<AtomicUsize>,
    binding: Option<AllowanceBinding>,
}

impl AgentRuntime for NoQueries {
    fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("Owned test forbids model requests")
    }

    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        anyhow::bail!("Owned test forbids triage requests")
    }

    fn allowance_binding(&self) -> Option<&AllowanceBinding> {
        self.binding.as_ref()
    }

    fn with_allowance_binding(
        &self,
        binding: AllowanceBinding,
    ) -> Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(Self {
            calls: Arc::clone(&self.calls),
            binding: Some(binding),
        }))
    }
}

#[test]
fn candidate_discovery_is_experimental_scan_work_without_a_phase_checkpoint() {
    let registry = ModuleRegistry::with_v2_builtins();
    let tool = registry
        .resolve_tool("taint-iris-next:finding-review")
        .unwrap();
    assert_eq!(tool.phase, ToolPhase::Scan);
    assert_eq!(tool.runtime_requirement, RuntimeRequirement::Always);
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
    assert!(!tool.phase_result);
    assert!(!registry.tool_is_discoverable(&tool.name));
    assert!(tool.description.contains("new source/sink evidence"));
    assert_eq!(
        crate::modules::tool_display_name(&tool.name),
        "Discover taint candidates"
    );
}

#[test]
fn prepared_candidate_discovery_reports_missing_context_without_querying_or_reviewing() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let mut config = V2Config::default();
    config.model = Some("openai:gpt-4.1".into());
    let runtime = NoQueries::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    approve_owned_allowance(&registry, &ctx);
    let input = registry
        .prepare_dispatch_input(
            "taint-iris-next:finding-review",
            json!({"backend":"structural","discoverSignals":false,"allowanceRef":{
                "schemaVersion":1,"investigationId":"owned-taint-audit","revision":1,"workId":"owned-prerequisite"}}),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    let result = registry
        .dispatch_prepared_input_with_runtime(input, &ctx, Some(&runtime))
        .unwrap();
    assert_eq!(result["status"], "failed");
    assert_eq!(result["data"]["status"], "missing-context");
    assert_eq!(result["data"]["missing"]["context"], true);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    assert!(store.list_findings(10).unwrap().is_empty());
}

fn approve_owned_allowance(registry: &ModuleRegistry, ctx: &ToolExecutionContext<'_>) {
    let approval = registry.prepare_dispatch_input("campaign:approve-allowance",
        json!({"investigationId":"owned-taint-audit","expectedRevision":0,"model":"openai:gpt-4.1",
        "maxProviderCalls":3,"protectedReviewCalls":1,"reason":"Owned offline no-query test"}), &ctx, None)
        .unwrap().authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(approval, &ctx, None)
        .unwrap();
}

#[test]
fn undeclared_scan_context_cannot_claim_scoped_candidate_support() {
    let registry = ModuleRegistry::with_v2_builtins();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let error = registry
        .prepare_dispatch_input(
            "taint-iris-next:finding-review",
            json!({"scanContextRef":{}}),
            &ctx,
            None,
        )
        .unwrap_err();
    assert!(error.to_string().contains("scanContextRef"));
}
