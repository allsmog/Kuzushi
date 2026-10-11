use super::*;
use crate::findings::{
    Finding, FindingStore, ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor,
};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse};
use crate::{ModuleRegistry, V2Config, WorkspaceTarget};
use std::sync::{Arc, Mutex};

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
    config: V2Config,
    registry: ModuleRegistry,
    id: i64,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("hello.txt"),
            "Owned source for defensive lesson review. Never executed.\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .with_run_lifecycle("lesson-source", root.path(), || {
                store.insert_finding(
                    "lesson-source",
                    &Finding::new_tool(
                        "owned-fixture",
                        "greeting",
                        "hello.txt",
                        1,
                        None,
                        Severity::Info,
                        "Labeled synthetic historical observation",
                    ),
                )?;
                Ok(((), 1))
            })
            .unwrap();
        let id = store.list_all_findings().unwrap()[0].id.unwrap();
        store
            .append_user_review_decision(
                id,
                &ReviewDecision {
                    verdict: ReviewDecisionVerdict::Confirmed,
                    author: TriageAuthor::Human,
                    confidence: 1.0,
                    rationale: "Synthetic acceptance for generation testing".into(),
                    dismiss_reason: None,
                    actor: None,
                },
            )
            .unwrap();
        Self {
            root,
            workspace,
            store,
            config: V2Config {
                model: Some("openai-codex:gpt-5.5".into()),
                ..Default::default()
            },
            registry: ModuleRegistry::with_v2_builtins(),
            id,
        }
    }
    fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }
    fn dispatch(
        &self,
        name: &str,
        input: Value,
        runtime: Option<&dyn AgentRuntime>,
        authorize: bool,
    ) -> Result<Value> {
        let ctx = self.context();
        let mut prepared = self
            .registry
            .prepare_dispatch_input(name, input, &ctx, None)?;
        if authorize {
            prepared = prepared.authorize_explicit_headless();
        }
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, runtime)
    }
    fn approve(&self, calls: u64) {
        self.dispatch("campaign:approve-allowance",json!({"investigationId":"lesson-test","expectedRevision":0,"model":"openai-codex:gpt-5.5","maxProviderCalls":calls,"protectedReviewCalls":1,"reason":"Owned intercepted lesson test"}),None,true).unwrap();
    }
    fn input(&self) -> Value {
        json!({"findingId":self.id,"allowanceRef":{"schemaVersion":1,"investigationId":"lesson-test","revision":1,"workId":"one-lesson"}})
    }
}

#[derive(Clone)]
struct OfflineRuntime {
    binding: Option<crate::allowance::AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    response: AgentQueryResponse,
    effect: Option<Arc<dyn Fn() -> Result<()> + Send + Sync>>,
}

impl OfflineRuntime {
    fn new() -> Self {
        Self {
            binding: None,
            requests: Default::default(),
            response: AgentQueryResponse {
                structured: Some(
                    json!({"schemaVersion":1,"content":{"title":"Review source evidence","text":"Check the historical observation before reusing its claim.","applicability":"Defensive source review","limitations":"Synthetic historical example; captured source may be absent. Current source needs independent review."}}),
                ),
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
            .context("Approved admission is required")?;
        let reserved = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reserved, crate::runtime::RuntimeCostReport::UNAVAILABLE)?;
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
fn bounded_lesson_generation_saves_only_a_draft_and_protects_review_calls() {
    let fixture = Fixture::new();
    fixture.approve(2);
    let runtime = OfflineRuntime::new();
    let result = fixture
        .dispatch(
            "findings:lesson-generate",
            fixture.input(),
            Some(&runtime),
            true,
        )
        .unwrap();
    assert_eq!(result["data"]["lesson"]["state"], "draft");
    assert_eq!(result["data"]["lesson"]["author"], "model");
    let request = &runtime.requests.lock().unwrap()[0];
    assert_eq!(
        request.runtime_options.as_ref().unwrap().max_model_turns,
        Some(1)
    );
    assert!(
        request.prompt.contains("currentSourceRead") || request.prompt.contains("not_recorded")
    );
    assert!(fixture
        .dispatch(
            "findings:lesson-generate",
            fixture.input(),
            Some(&runtime),
            true
        )
        .is_err());
    assert_eq!(fixture.store.finding_lessons(50, 0).unwrap().rows.len(), 1);
    assert_eq!(fixture.store.list_all_review_decisions().unwrap().len(), 1);
}

#[test]
fn malformed_and_truncated_outputs_do_not_repair_or_save_lessons() {
    for response in [
        AgentQueryResponse {
            text: "not JSON".into(),
            ..Default::default()
        },
        AgentQueryResponse {
            truncated: true,
            ..OfflineRuntime::new().response
        },
    ] {
        let fixture = Fixture::new();
        fixture.approve(2);
        let runtime = OfflineRuntime {
            response,
            ..OfflineRuntime::new()
        };
        assert!(fixture
            .dispatch(
                "findings:lesson-generate",
                fixture.input(),
                Some(&runtime),
                true
            )
            .is_err());
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
        assert!(fixture
            .store
            .finding_lessons(50, 0)
            .unwrap()
            .rows
            .is_empty());
    }
}

#[test]
fn lesson_study_freezes_origin_and_never_publishes_map() {
    let fixture = Fixture::new();
    let result=fixture.dispatch("campaign:context-study",json!({"campaignId":"lesson-plan","investigationId":"lesson-test","generationTool":"findings:lesson-generate","contextInput":{"findingId":fixture.id}}),None,false).unwrap();
    assert!(result["data"]["input"]["originRef"].is_object());
    assert!(result["data"]["input"].get("allowanceRef").is_none());
    let receipt: crate::capabilities::campaign::ContextStudyReceipt =
        serde_json::from_value(result["data"].clone()).unwrap();
    assert_eq!(receipt.job_count(), 1);
    fixture.dispatch("campaign:approve-allowance",json!({"investigationId":"lesson-test","expectedRevision":0,"model":receipt.model,"maxProviderCalls":2,"protectedReviewCalls":1,"reason":"Explicit frozen lesson work","campaignId":receipt.campaign_id,"campaignPlanSha256":receipt.plan_sha256,"campaignJobs":1,"maxJobAttempts":1}),None,true).unwrap();
    assert!(fixture
        .dispatch(
            "campaign:context-map",
            json!({"campaignId":receipt.campaign_id,"expectedPlanSha256":receipt.plan_sha256}),
            None,
            false
        )
        .unwrap_err()
        .to_string()
        .contains("cannot complete Map"));
    let _ = &fixture.root;
    assert!(
        crate::workflow_attempts::load_phase_attempt_ledger_v2(fixture.workspace.root())
            .unwrap()
            .attempts
            .is_empty()
    );
}

#[test]
fn frozen_origin_change_is_refused_before_the_model_request() {
    let fixture = Fixture::new();
    fixture.approve(2);
    let runtime = OfflineRuntime::new();
    let origin = fixture
        .store
        .lesson_origin(fixture.workspace.root(), fixture.id)
        .unwrap();
    let mut input = fixture.input();
    input["originRef"] = serde_json::to_value(origin).unwrap();
    fixture
        .store
        .append_dismissal(
            fixture.id,
            crate::findings::DismissReason::FalsePositive,
            "Reassessed synthetic fixture",
            "operator",
        )
        .unwrap();
    assert!(fixture
        .dispatch("findings:lesson-generate", input, Some(&runtime), true)
        .is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn confirmation_change_during_generation_does_not_save_a_draft() {
    let fixture = Fixture::new();
    fixture.approve(2);
    let db = fixture.workspace.findings_db_path();
    let id = fixture.id;
    let runtime = OfflineRuntime {
        effect: Some(Arc::new(move || {
            FindingStore::open(&db)?
                .append_dismissal(
                    id,
                    crate::findings::DismissReason::FalsePositive,
                    "Withdrawn synthetic confirmation",
                    "operator",
                )
                .map(|_| ())
        })),
        ..OfflineRuntime::new()
    };
    assert!(fixture
        .dispatch(
            "findings:lesson-generate",
            fixture.input(),
            Some(&runtime),
            true
        )
        .is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(fixture
        .store
        .finding_lessons(50, 0)
        .unwrap()
        .rows
        .is_empty());
}

#[test]
fn bounded_captured_source_rejects_corruption_and_discloses_omission() {
    use crate::content_store::{ContentStore, ObjectKind};
    let root = tempfile::tempdir().unwrap();
    let store = ContentStore::open(root.path()).unwrap();
    let object = store
        .put_bytes(ObjectKind::Blob, b"Owned immutable source")
        .unwrap();
    assert_eq!(
        store.get_blob_bounded(&object.hash, 32).unwrap().unwrap(),
        b"Owned immutable source"
    );
    assert!(store.get_blob_bounded(&object.hash, 4).unwrap().is_none());
    std::fs::write(store.object_path(&object.hash), b"Changed source").unwrap();
    assert!(store.get_blob_bounded(&object.hash, 32).is_err());
}

#[test]
fn cancellation_after_a_provider_attempt_does_not_save_a_lesson() {
    let fixture = Fixture::new();
    fixture.approve(2);
    let cancel = crate::ScanCancellation::default();
    let signal = cancel.clone();
    let runtime = OfflineRuntime {
        effect: Some(Arc::new(move || {
            signal.cancel();
            Ok(())
        })),
        ..OfflineRuntime::new()
    };
    let mut ctx = fixture.context();
    ctx.cancellation = Some(&cancel);
    let prepared = fixture
        .registry
        .prepare_dispatch_input("findings:lesson-generate", fixture.input(), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    assert!(fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&runtime))
        .is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(fixture
        .store
        .finding_lessons(50, 0)
        .unwrap()
        .rows
        .is_empty());
}
