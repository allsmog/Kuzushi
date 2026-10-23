use super::*;
use crate::modules::ModuleRegistry;
use crate::runtime::AgentQueryResponse;
use crate::workspace::{ProposedScanScope, ScanScopeDraft, ScopeCoverageApproval};
use std::sync::{Arc, Mutex};
mod evidence;

struct Fixture {
    root: tempfile::TempDir,
    workspace: crate::WorkspaceTarget,
    config: crate::V2Config,
    registry: ModuleRegistry,
    scope: ScanScopeRef,
    active: ThreatModelRef,
    trace: crate::run_artifacts::TraceHandle,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        for dir in ["app", "adapter", "shared", "other"] {
            std::fs::create_dir(root.path().join(dir)).unwrap();
        }
        for (path, marker) in [
            ("app/one.rs", "OWNED_APP"),
            ("adapter/two.rs", "OWNED_ADAPTER"),
            ("shared/context.rs", "OWNED_SHARED"),
            ("other/other.rs", "UNSELECTED_SIBLING"),
            ("loose.rs", "UNSELECTED_ROOT"),
        ] {
            std::fs::write(root.path().join(path), format!("// {marker}\n")).unwrap();
        }
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let config = crate::V2Config {
            model: Some("openai-codex:gpt-5.5".into()),
            ..Default::default()
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let draft = ScanScopeDraft {
            schema_version: 1,
            scopes: vec![
                scope("app", &["app", "adapter"]),
                scope("other", &["other"]),
                scope("loose", &["loose.rs"]),
                scope("integration", &["shared"]),
            ],
            shared_scope: Some(scope("shared", &["shared"])),
            shared_discovery: false,
            exclusions: Vec::new(),
        };
        let initial = crate::workspace::create_scan_scope_proposal(&ctx, Some(draft)).unwrap();
        let accepted = crate::workspace::accept_scan_scope_proposal(
            &ctx,
            &initial.reference,
            ScopeCoverageApproval {
                inventory_limitations: true,
                exclusions: false,
                overlapping_discovery: false,
            },
        )
        .unwrap();
        let imported = registry
            .execute_tool(
                "threat-model:import",
                json!({"document":document(),"label":"Active original","activate":true}),
                &ctx,
            )
            .unwrap();
        let active = serde_json::from_value(imported["data"]["modelRef"].clone()).unwrap();
        let trace = crate::run_artifacts::TraceHandle::jsonl(root.path(), "scope-context-test");
        Self {
            root,
            workspace,
            config,
            registry,
            scope: ScanScopeRef {
                proposal: accepted.reference,
                scope_id: "app".into(),
            },
            active,
            trace,
        }
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
    fn plan(&self, id: &str) -> crate::capabilities::campaign::ContextStudyReceipt {
        let result=self.dispatch("campaign:context-study",json!({"campaignId":id,"investigationId":"group-test","contextInput":{"scanScopeRef":self.scope,"inheritedContextRef":self.active,"maxSourceBytes":8192},
            "scopeStudyOrigin":{"schemaVersion":1,"scopeProposalRef":self.scope.proposal,"scopeCases":[{"scopeId":"app","passes":3},{"scopeId":"other","passes":3,"threatModelRef":null}],"scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":self.active}}}),None,false).unwrap();
        serde_json::from_value(result["data"].clone()).unwrap()
    }
    fn approve(&self, receipt: &crate::capabilities::campaign::ContextStudyReceipt) -> Value {
        self.dispatch("campaign:approve-allowance",json!({"investigationId":"group-test","expectedRevision":0,"model":receipt.model,"maxProviderCalls":2,"protectedReviewCalls":1,"reason":"Owned file-group context fixture","campaignId":receipt.campaign_id,"campaignPlanSha256":receipt.plan_sha256,"campaignJobs":1,"maxJobAttempts":1}),None,true).unwrap();
        let allowance = receipt.load_allowance(self.root.path()).unwrap().unwrap();
        receipt.bound_input(&allowance).unwrap()
    }
}

fn scope(id: &str, paths: &[&str]) -> ProposedScanScope {
    ProposedScanScope {
        id: id.into(),
        name: id.into(),
        paths: paths.iter().map(|p| (*p).into()).collect(),
        rationale: "Owned context boundary".into(),
        shared_dependencies: Vec::new(),
        open_questions: Vec::new(),
    }
}

fn document() -> Value {
    json!({"version":"1","methodology":"stride","systemContext":"Owned architecture explanation", "dfd":{"nodes":[{"id":"app","name":"Owned component","purpose":"Owned explanation","type":"process","trustZone":"internal","sourceRefs":["app/one.rs:1"]}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{},"openQuestions":["Who owns the boundary?"]})
}

#[test]
fn explicit_goal_guidance_preserves_file_group_membership_and_active_context() {
    let fixture = Fixture::new();
    let brief = fixture.dispatch("campaign:brief", json!({"mode":"save","expectedRevision":0,"text":"Scoped goal: explain shared dependencies without adding discovery."}), None, false).unwrap();
    let planned = fixture.dispatch("campaign:context-study", json!({"campaignId":"guided-group","investigationId":"group-test",
        "briefRef":brief["data"]["brief"]["reference"],"useBriefGuidance":true,
        "contextInput":{"scanScopeRef":fixture.scope,"inheritedContextRef":fixture.active,"maxSourceBytes":8192}}), None, false).unwrap();
    let receipt = serde_json::from_value(planned["data"].clone()).unwrap();
    let input = fixture.approve(&receipt);
    let runtime = OfflineRuntime::new(document());
    let result = fixture
        .dispatch("threat-model:build", input, Some(&runtime), true)
        .unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let supplied = serde_json::to_string(&requests[0]).unwrap();
    assert!(supplied.contains("Scoped goal"));
    assert!(!supplied.contains("UNSELECTED_SIBLING"));
    assert!(!supplied.contains("UNSELECTED_ROOT"));
    assert_eq!(
        result["data"]["document"]["provenance"]["operatorIntent"]["reference"],
        brief["data"]["brief"]["reference"]
    );
    assert_eq!(
        load_active_threat_model(fixture.root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        fixture.active
    );
}

#[derive(Clone)]
struct OfflineRuntime {
    binding: Option<crate::allowance::AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    response: AgentQueryResponse,
    effect: Option<Arc<dyn Fn() -> Result<()> + Send + Sync>>,
}
impl OfflineRuntime {
    fn new(document: Value) -> Self {
        Self {
            binding: None,
            requests: Default::default(),
            response: AgentQueryResponse {
                structured: Some(document),
                ..Default::default()
            },
            effect: None,
        }
    }
}
impl AgentRuntime for OfflineRuntime {
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
            .context("Approved admission required")?;
        let reservation = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reservation, crate::runtime::RuntimeCostReport::UNAVAILABLE)?;
        if let Some(effect) = &self.effect {
            effect()?;
        }
        Ok(self.response.clone())
    }
    fn triage_finding_blocking(&self, _: crate::TriageRequest) -> Result<crate::TriageOutcome> {
        unreachable!()
    }
}

#[test]
fn scoped_context_one_approved_call_reads_disjoint_members_and_shared_context_only() {
    let fixture = Fixture::new();
    let receipt = fixture.plan("group-context");
    assert_eq!(receipt.job_count(), 1);
    assert_eq!(
        receipt.scope_study_origin.as_ref().unwrap().scope_cases[1].threat_model_ref,
        Some(Value::Null)
    );
    let input = fixture.approve(&receipt);
    let runtime = OfflineRuntime::new(document());
    let result = fixture
        .dispatch("threat-model:build", input, Some(&runtime), false)
        .unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let prompt = &requests[0].prompt;
    for marker in ["OWNED_APP", "OWNED_ADAPTER", "OWNED_SHARED"] {
        assert!(prompt.contains(marker));
    }
    for marker in ["UNSELECTED_SIBLING", "UNSELECTED_ROOT"] {
        assert!(!prompt.contains(marker));
    }
    assert_eq!(
        requests[0]
            .runtime_options
            .as_ref()
            .unwrap()
            .max_model_turns,
        Some(1)
    );
    assert!(requests[0].tool_policy.tools.is_empty());
    assert_eq!(result["data"]["activated"], false);
    assert_eq!(
        result["data"]["scopeContext"]["completeRepositoryCoverage"],
        false
    );
    assert!(result["data"]["costUsd"].is_null());
    assert_eq!(
        load_active_threat_model(fixture.root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        fixture.active
    );
    let allowance = receipt
        .load_allowance(fixture.root.path())
        .unwrap()
        .unwrap();
    assert_eq!(allowance.committed_calls, 1);
    assert_eq!(allowance.protected_review_remaining(), 1);
    let reference: ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    assert_eq!(
        load_exact_threat_model(fixture.root.path(), &reference).unwrap(),
        result["data"]["document"]
    );
}

#[test]
fn scoped_context_requires_fixed_approval_and_invalid_paths_fail_before_model() {
    let fixture = Fixture::new();
    let receipt = fixture.plan("group-denied");
    let runtime = OfflineRuntime::new(document());
    assert!(fixture
        .dispatch(
            "threat-model:build",
            receipt.input.clone(),
            Some(&runtime),
            false
        )
        .is_err());
    let mut input = receipt.input.clone();
    input["scanScopeRef"]["scopeId"] = json!("missing");
    assert!(validate_scoped_context_input(&input, &fixture.context()).is_err());
    input["scanScopeRef"] = json!(fixture.scope);
    input["target"] = json!("/private/tmp");
    assert!(validate_scoped_context_input(&input, &fixture.context()).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn scoped_context_invalid_citation_has_one_call_no_repair_and_no_revision() {
    let fixture = Fixture::new();
    let receipt = fixture.plan("group-invalid");
    let input = fixture.approve(&receipt);
    let mut output = document();
    output["dfd"]["nodes"][0]["sourceRefs"] = json!(["other/other.rs:1"]);
    let runtime = OfflineRuntime::new(output);
    assert!(fixture
        .dispatch("threat-model:build", input, Some(&runtime), false)
        .is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(
        load_threat_model_manifest(fixture.root.path())
            .unwrap()
            .unwrap()
            .models
            .len(),
        1
    );
    assert!(crate::run_artifacts::read_run_artifact_text_bounded(
        fixture.root.path(),
        "scope-context-test",
        "rejected-context-output.txt",
        128 * 1024
    )
    .is_ok());
}

#[test]
fn scoped_context_source_drift_after_paid_reply_preserves_spending_without_commit() {
    let fixture = Fixture::new();
    let receipt = fixture.plan("group-drift");
    let input = fixture.approve(&receipt);
    let path = fixture.root.path().join("app/one.rs");
    let mut runtime = OfflineRuntime::new(document());
    runtime.effect = Some(Arc::new(move || {
        std::fs::write(&path, "// CHANGED\n")?;
        Ok(())
    }));
    assert!(fixture
        .dispatch("threat-model:build", input, Some(&runtime), false)
        .is_err());
    assert_eq!(
        load_threat_model_manifest(fixture.root.path())
            .unwrap()
            .unwrap()
            .models
            .len(),
        1
    );
    assert_eq!(
        receipt
            .load_allowance(fixture.root.path())
            .unwrap()
            .unwrap()
            .committed_calls,
        1
    );
}

#[test]
fn scoped_context_preparation_cannot_append_root_map_work() {
    let fixture = Fixture::new();
    let result=fixture.dispatch("campaign:context-study",json!({"campaignId":"group-extra","investigationId":"group-test","contextInput":{"scanScopeRef":fixture.scope},"preparationJobs":[{"tool":"context:build","input":{}}]}),None,false);
    assert!(result.is_err());
    assert!(!fixture
        .root
        .path()
        .join(".kuzushi/v3/campaigns/group-extra/plan.json")
        .exists());
}

#[test]
fn scoped_context_selected_text_regeneration_preserves_literal_group_source() {
    let mut fixture = Fixture::new();
    let first = fixture.plan("group-parent");
    let input = fixture.approve(&first);
    let created = fixture
        .dispatch(
            "threat-model:build",
            input,
            Some(&OfflineRuntime::new(document())),
            false,
        )
        .unwrap();
    let reference = &created["data"]["modelRef"];
    let planned=fixture.dispatch("campaign:context-study",json!({"campaignId":"group-text","investigationId":"group-test","generationTool":"threat-model:regenerate","contextInput":{"threatModelRef":reference,"fields":["/dfd/nodes/0/purpose"]}}),None,false).unwrap();
    let receipt: crate::capabilities::campaign::ContextStudyReceipt =
        serde_json::from_value(planned["data"].clone()).unwrap();
    fixture.dispatch("campaign:approve-allowance",json!({"investigationId":"group-test","expectedRevision":1,"model":receipt.model,"maxProviderCalls":3,"protectedReviewCalls":1,"reason":"One additional owned text request","campaignId":receipt.campaign_id,"campaignPlanSha256":receipt.plan_sha256,"campaignJobs":1,"maxJobAttempts":1}),None,true).unwrap();
    let input = receipt
        .bound_input(
            &receipt
                .load_allowance(fixture.root.path())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    let runtime = OfflineRuntime::new(
        json!({"schemaVersion":1,"edits":[{"pointer":"/dfd/nodes/0/purpose","text":"Reviewed group explanation"}]}),
    );
    fixture.trace = crate::run_artifacts::TraceHandle::jsonl(fixture.root.path(), "group-text-run");
    let result = fixture
        .dispatch("threat-model:regenerate", input, Some(&runtime), false)
        .unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    for marker in ["OWNED_APP", "OWNED_ADAPTER", "OWNED_SHARED"] {
        assert!(requests[0].prompt.contains(marker));
    }
    for marker in ["UNSELECTED_SIBLING", "UNSELECTED_ROOT"] {
        assert!(!requests[0].prompt.contains(marker));
    }
    assert_eq!(
        result["data"]["document"]["dfd"]["nodes"][0]["purpose"],
        "Reviewed group explanation"
    );
    assert_eq!(
        load_active_threat_model(fixture.root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        fixture.active
    );
}
