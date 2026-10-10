use super::*;
use crate::{
    modules::ModuleRegistry,
    runtime::{AgentQueryRequest, AgentQueryResponse},
};
use std::sync::{Arc, Mutex};
mod workflow;

struct Fixture {
    root: tempfile::TempDir,
    workspace: crate::WorkspaceTarget,
    config: crate::V2Config,
    registry: ModuleRegistry,
    selected: ThreatModelRef,
    active: ThreatModelRef,
    trace: crate::run_artifacts::TraceHandle,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("main.rs"),
            "// Owned architecture fixture, never executed.\nfn main() { println!(\"hello\"); }\n",
        )
        .unwrap();
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let config = crate::V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..Default::default()
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "regeneration-test");
        let mut fixture = Self {
            root,
            workspace,
            config,
            registry,
            selected: placeholder_ref(),
            active: placeholder_ref(),
            trace,
        };
        fixture.selected = fixture.import("Selected original");
        fixture.active = fixture.import("Other active");
        let _=fixture.dispatch("campaign:approve-allowance",json!({"investigationId":"regeneration","expectedRevision":0,"model":"openai-codex:gpt-5.5","maxProviderCalls":2,"protectedReviewCalls":1,"reason":"Owned offline regeneration test"}),None,true).unwrap();
        fixture
    }
    fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: Some(&self.trace),
            cancellation: None,
            authorization: Default::default(),
        }
    }
    fn dispatch(
        &self,
        tool: &str,
        input: Value,
        runtime: Option<&dyn AgentRuntime>,
        authorize: bool,
    ) -> Result<Value> {
        let ctx = self.context();
        let mut prepared = self
            .registry
            .prepare_dispatch_input(tool, input, &ctx, None)?;
        if authorize {
            prepared = prepared.authorize_explicit_headless();
        }
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, runtime)
    }
    fn import(&self, label: &str) -> ThreatModelRef {
        let document = json!({"version":"1","methodology":"stride","systemContext":label,"userEdited":true,"dfd":{"nodes":[{"id":"app","name":"App","type":"process","trustZone":"internal","description":"Operator description","purpose":"Original purpose"}],"flows":[],"trustBoundaries":[]},"openQuestions":[{"question":"Who owns input?","answer":"Operator answer"}],"threats":[],"summary":{}});
        let mut ctx = self.context();
        ctx.trace = None;
        let result = self
            .registry
            .execute_tool(
                "threat-model:import",
                json!({"document":document,"label":label,"activate":true}),
                &ctx,
            )
            .unwrap();
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap()
    }
    fn input(&self) -> Value {
        json!({"threatModelRef":self.selected,"fields":["/dfd/nodes/0/purpose"],"thinkingLevel":"medium","allowanceRef":{"schemaVersion":1,"investigationId":"regeneration","revision":1,"workId":"one-regeneration"}})
    }
}

fn placeholder_ref() -> ThreatModelRef {
    ThreatModelRef {
        model_id: ThreatModelId::new(),
        revision_id: ThreatModelRevisionId::new(),
        sha256: format!("sha256:{}", "0".repeat(64)),
    }
}

#[derive(Clone)]
struct OfflineRegenerationRuntime {
    binding: Option<crate::allowance::AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    response: AgentQueryResponse,
    during_query: Option<Arc<dyn Fn() -> Result<()> + Send + Sync>>,
}
impl OfflineRegenerationRuntime {
    fn new(value: Value) -> Self {
        Self {
            binding: None,
            requests: Default::default(),
            response: AgentQueryResponse {
                structured: Some(value),
                ..Default::default()
            },
            during_query: None,
        }
    }
}
impl AgentRuntime for OfflineRegenerationRuntime {
    fn with_allowance_binding(
        &self,
        binding: crate::allowance::AllowanceBinding,
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
            .context("Shared approved admission is required")?;
        let reservation = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reservation, crate::runtime::RuntimeCostReport::UNAVAILABLE)?;
        if let Some(effect) = &self.during_query {
            effect()?;
        }
        Ok(self.response.clone())
    }
    fn triage_finding_blocking(&self, _: crate::TriageRequest) -> Result<crate::TriageOutcome> {
        unreachable!()
    }
}

fn response() -> Value {
    json!({"schemaVersion":1,"edits":[{"pointer":"/dfd/nodes/0/purpose","text":"Proposed explanatory purpose"}]})
}

#[test]
fn one_shared_request_saves_inactive_copy_and_preserves_operator_text_and_active_context() {
    let fixture = Fixture::new();
    let runtime = OfflineRegenerationRuntime::new(response());
    let original = load_exact_threat_model(fixture.root.path(), &fixture.selected).unwrap();
    let mirror = fs::read(persistent_threat_model_path(fixture.root.path())).unwrap();
    let before = load_threat_model_manifest(fixture.root.path())
        .unwrap()
        .unwrap();
    let result = fixture
        .dispatch(
            "threat-model:regenerate",
            fixture.input(),
            Some(&runtime),
            false,
        )
        .unwrap();
    let reference: ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    assert_eq!(result["data"]["activated"], false);
    assert_ne!(reference.model_id, fixture.selected.model_id);
    let copy = load_exact_threat_model(fixture.root.path(), &reference).unwrap();
    assert_eq!(copy["systemContext"], original["systemContext"]);
    assert_eq!(copy["openQuestions"], original["openQuestions"]);
    assert_eq!(
        copy["dfd"]["nodes"][0]["description"],
        "Operator description"
    );
    assert_eq!(
        copy["dfd"]["nodes"][0]["purpose"],
        "Proposed explanatory purpose"
    );
    assert!(copy.get("verification").is_none());
    let after = load_threat_model_manifest(fixture.root.path())
        .unwrap()
        .unwrap();
    assert_eq!(after.active, Some(fixture.active.clone()));
    assert_eq!(after.models[..2], before.models[..2]);
    assert_eq!(
        after.models[2].revisions[0].source_revision_id,
        Some(fixture.selected.revision_id.clone())
    );
    assert_eq!(after.models[2].scope, before.models[0].scope);
    assert_eq!(
        fs::read(persistent_threat_model_path(fixture.root.path())).unwrap(),
        mirror
    );
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].model, "openai-codex:gpt-5.5");
    assert!(requests[0].tool_policy.tools.is_empty() && !requests[0].tool_policy.mcps);
    assert!(requests[0].prompt.contains("Owned architecture fixture"));
    assert!(requests[0].prompt.contains("source"));
}

#[test]
fn malformed_partial_extra_fields_and_source_drift_publish_no_copy_or_repair() {
    for (value, truncated, drift) in [
        (json!({"schemaVersion":1,"edits":[]}), false, false),
        (response(), true, false),
        (response(), false, true),
    ] {
        let fixture = Fixture::new();
        let mut runtime = OfflineRegenerationRuntime::new(value);
        runtime.response.truncated = truncated;
        if drift {
            let path = fixture.root.path().join("main.rs");
            runtime.during_query = Some(Arc::new(move || {
                fs::write(&path, "// Changed owned source\n")?;
                Ok(())
            }));
        }
        let before = fs::read(threat_model_manifest_path(fixture.root.path())).unwrap();
        assert!(fixture
            .dispatch(
                "threat-model:regenerate",
                fixture.input(),
                Some(&runtime),
                false
            )
            .is_err());
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
        assert_eq!(
            fs::read(threat_model_manifest_path(fixture.root.path())).unwrap(),
            before
        );
    }
}

#[test]
fn allowance_and_valid_source_are_required_before_any_provider_request() {
    let fixture = Fixture::new();
    let runtime = OfflineRegenerationRuntime::new(response());
    let mut input = fixture.input();
    input.as_object_mut().unwrap().remove("allowanceRef");
    assert!(fixture
        .dispatch("threat-model:regenerate", input, Some(&runtime), false)
        .is_err());
    fs::write(fixture.root.path().join("main.rs"), "// Changed source\n").unwrap();
    assert!(fixture
        .dispatch(
            "threat-model:regenerate",
            fixture.input(),
            Some(&runtime),
            false
        )
        .is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn regeneration_stamp_preserves_operator_provenance_and_clears_old_check() {
    let root = tempfile::tempdir().unwrap();
    let reference = commit_test_model(root.path(), "Original");
    let mut document = json!({"userEdited":true,"verification":{"verdict":"verified"},"provenance":{"treeHash":"original","operatorEdit":{"fields":["/systemContext"]}}});
    stamp_regeneration(
        &mut document,
        &reference,
        &json!({"model":"selected","synthesisRequests":1}),
    )
    .unwrap();
    assert_eq!(document["userEdited"], true);
    assert_eq!(document["provenance"]["treeHash"], "original");
    assert_eq!(
        document["provenance"]["operatorEdit"]["fields"],
        json!(["/systemContext"])
    );
    assert_eq!(document["provenance"]["regeneration"]["accepted"], false);
    assert_eq!(
        document["provenance"]["regeneration"]["sourceModelRef"],
        json!(reference)
    );
    assert!(document.get("verification").is_none());
}
