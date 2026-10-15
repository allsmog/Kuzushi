use crate::modules::ModuleMaturity;
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime};
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const MODEL: &str = "openai:gpt-4.1";

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    config: V2Config,
    registry: ModuleRegistry,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("note.md"),
            "OWNED_SOURCE_MARKER: inert architecture notes.\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        Self {
            root,
            workspace,
            config: V2Config {
                model: Some(MODEL.into()),
                ..Default::default()
            },
            registry: ModuleRegistry::with_v2_builtins(),
        }
    }

    fn context<'a>(
        &'a self,
        cancellation: Option<&'a crate::scan::ScanCancellation>,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation,
            authorization: Default::default(),
        }
    }

    fn dispatch(
        &self,
        name: &str,
        input: Value,
        runtime: Option<&dyn AgentRuntime>,
        cancellation: Option<&crate::scan::ScanCancellation>,
    ) -> anyhow::Result<Value> {
        let ctx = self.context(cancellation);
        let prepared = self
            .registry
            .prepare_dispatch_input(name, input, &ctx, None)?
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, runtime)
    }

    fn approved_input(&self) -> Value {
        self.dispatch(
            "campaign:approve-allowance",
            json!({"investigationId":"xray-contract",
            "expectedRevision":0,"model":MODEL,"maxProviderCalls":2,"protectedReviewCalls":1,
            "reason":"Owned offline experimental executor audit; no network or source execution"}),
            None,
            None,
        )
        .unwrap();
        json!({"allowanceRef":{"schemaVersion":1,"investigationId":"xray-contract","revision":1,"workId":"xray-report"}})
    }

    fn allowance(&self) -> crate::allowance::AllowanceSnapshot {
        crate::SpendLimiter::read_allowance_snapshot(
            &self.workspace.findings_db_path(),
            "xray-contract",
        )
        .unwrap()
    }
}

#[derive(Clone, Default)]
struct SyntheticRuntime {
    binding: Option<crate::allowance::AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    cancel_after_query: Option<crate::scan::ScanCancellation>,
}

impl AgentRuntime for SyntheticRuntime {
    fn allowance_binding(&self) -> Option<&crate::allowance::AllowanceBinding> {
        self.binding.as_ref()
    }
    fn with_allowance_binding(
        &self,
        binding: crate::allowance::AllowanceBinding,
    ) -> anyhow::Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(Self {
            binding: Some(binding),
            ..self.clone()
        }))
    }

    fn query_blocking(&self, request: AgentQueryRequest) -> anyhow::Result<AgentQueryResponse> {
        let binding = self
            .binding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Shared admission required"))?;
        let reserved = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reserved, crate::runtime::RuntimeCostReport::UNAVAILABLE)?;
        if let Some(cancel) = &self.cancel_after_query {
            cancel.cancel();
        }
        Ok(AgentQueryResponse {
            structured: Some(synthetic_reports()),
            ..Default::default()
        })
    }

    fn triage_finding_blocking(
        &self,
        _: crate::TriageRequest,
    ) -> anyhow::Result<crate::TriageOutcome> {
        unreachable!()
    }
}

fn synthetic_reports() -> Value {
    json!({"xRayMarkdown":"# Labeled synthetic architecture claim\n## X-Ray Verdict\nWATCH\nNot a security assessment.\n",
        "entryPointsMarkdown":"# Labeled synthetic report\n> Example | 1 entry point | 1 permissionless | 0 role-gated | 0 admin-only\n",
        "invariantsMarkdown":"# Labeled synthetic report\n### G-1 Preserve operator text\n",
        "architectureSvg":"<svg xmlns=\"http://www.w3.org/2000/svg\"><title>Labeled synthetic report</title></svg>"})
}

#[test]
fn generation_is_experimental_auxiliary_and_exact_dispatch_stays_registered() {
    let registry = ModuleRegistry::with_v2_builtins();
    for tool in ["x-ray:run", "x-ray:x-ray"] {
        let descriptor = registry.resolve_tool(tool).unwrap();
        assert_eq!(descriptor.discovery_maturity, Some(ModuleMaturity::Labs));
        assert!(!registry.tool_is_discoverable(tool));
        assert_eq!(crate::modules::phase_result_phase(descriptor), None);
    }
    assert!(registry.tool_is_discoverable("x-ray:read"));
}

#[test]
fn real_prepared_executor_and_reader_preserve_accounting_without_claiming_grounding() {
    for tool in ["x-ray:run", "x-ray:x-ray"] {
        let fixture = Fixture::new();
        let runtime = SyntheticRuntime::default();
        let mut input = fixture.approved_input();
        input["effort"] = json!("medium");
        let result = fixture.dispatch(tool, input, Some(&runtime), None).unwrap();
        assert_eq!(result["status"], "completed");
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
        assert_eq!(
            runtime.requests.lock().unwrap()[0]
                .thinking_level
                .as_deref(),
            Some("medium")
        );
        assert!(!runtime.requests.lock().unwrap()[0]
            .prompt
            .contains("OWNED_SOURCE_MARKER"));
        assert!(result["data"].get("modelRef").is_none());
        assert!(result["summary"]
            .as_str()
            .unwrap()
            .contains("Experimental report generation"));
        assert!(result["summary"]
            .as_str()
            .unwrap()
            .contains("Cost:         unknown"));
        assert_eq!(result["artifacts"].as_array().unwrap().len(), 4);
        let read = fixture
            .dispatch("x-ray:read", json!({}), None, None)
            .unwrap();
        assert_eq!(read["data"]["entryPointCounts"]["total"], 1);
        assert_eq!(
            read["data"]["readProvenance"]["sourceFreshness"],
            "not-assessed"
        );
        assert_source_and_review_capacity_preserved(&fixture);
    }
}

fn assert_source_and_review_capacity_preserved(fixture: &Fixture) {
    assert_eq!(
        std::fs::read_to_string(fixture.root.path().join("note.md")).unwrap(),
        "OWNED_SOURCE_MARKER: inert architecture notes.\n"
    );
    let snapshot = fixture.allowance();
    assert_eq!(snapshot.committed_calls, 1);
    assert_eq!(snapshot.unresolved_calls, 0);
    assert_eq!(snapshot.protected_review_remaining(), 1);
}

#[test]
fn unapproved_generation_starts_no_query_or_reports() {
    let fixture = Fixture::new();
    let runtime = SyntheticRuntime::default();
    assert!(fixture
        .dispatch("x-ray:run", json!({}), Some(&runtime), None)
        .is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert!(!fixture.root.path().join("x-ray").exists());
}

#[test]
fn call_allowance_does_not_authorize_target_writes() {
    let fixture = Fixture::new();
    let input = fixture.approved_input();
    let runtime = SyntheticRuntime::default();
    let ctx = fixture.context(None);
    let prepared = fixture
        .registry
        .prepare_dispatch_input("x-ray:run", input, &ctx, None)
        .unwrap();
    assert!(fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.allowance().committed_calls, 0);
    assert!(!fixture.root.path().join("x-ray").exists());
}

#[test]
fn inherited_review_capacity_cannot_fund_target_write_context_generation() {
    let fixture = Fixture::new();
    fixture.approved_input();
    let ledger = Arc::new(crate::SpendLimiter::open(fixture.workspace.findings_db_path()).unwrap());
    let work = crate::allowance::AllowanceWork {
        investigation_id: "xray-contract".into(),
        revision: 1,
        model: MODEL.into(),
        run_id: "review-parent".into(),
        work_id: "review-work".into(),
        work: crate::allowance::InvestigationWork::Review,
    };
    let runtime = SyntheticRuntime {
        binding: Some(crate::allowance::AllowanceBinding::new(ledger, work).unwrap()),
        ..Default::default()
    };
    let error = fixture
        .dispatch("x-ray:run", json!({}), Some(&runtime), None)
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("cannot borrow a parent Review allowance"));
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert_eq!(fixture.allowance().committed_calls, 0);
    assert_eq!(fixture.allowance().protected_review_remaining(), 1);
    assert!(!fixture.root.path().join("x-ray").exists());
}

#[test]
fn cancellation_before_generation_spends_nothing_and_writes_no_reports() {
    let fixture = Fixture::new();
    let input = fixture.approved_input();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let runtime = SyntheticRuntime::default();
    assert!(fixture
        .dispatch("x-ray:run", input, Some(&runtime), Some(&cancellation))
        .is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert!(!fixture.root.path().join("x-ray").exists());
}

#[test]
fn cancellation_after_query_retains_consumption_without_publishing_reports() {
    let fixture = Fixture::new();
    let cancellation = crate::scan::ScanCancellation::default();
    let runtime = SyntheticRuntime {
        cancel_after_query: Some(cancellation.clone()),
        ..Default::default()
    };
    let error = fixture
        .dispatch(
            "x-ray:run",
            fixture.approved_input(),
            Some(&runtime),
            Some(&cancellation),
        )
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(!fixture.root.path().join("x-ray").exists());
    assert_eq!(fixture.allowance().committed_calls, 1);
    assert_eq!(fixture.allowance().unresolved_calls, 0);
}

#[test]
fn experimental_generation_has_no_supported_finite_map_study() {
    let fixture = Fixture::new();
    assert!(fixture
        .dispatch(
            "campaign:context-study",
            json!({"campaignId":"unsupported-xray-study",
        "generationTool":"x-ray:run","contextInput":{}}),
            None,
            None
        )
        .is_err());
    assert!(!fixture
        .root
        .path()
        .join(".kuzushi/v3/campaigns/unsupported-xray-study/plan.json")
        .exists());
}
