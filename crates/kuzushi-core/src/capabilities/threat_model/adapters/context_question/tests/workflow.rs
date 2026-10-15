use super::*;
use crate::{
    modules::ModuleRegistry,
    runtime::{AgentQueryRequest, AgentQueryResponse},
};
use std::sync::{Arc, Mutex};

const MODEL: &str = "openai-codex:gpt-5.5";
struct Fixture {
    root: tempfile::TempDir,
    workspace: crate::WorkspaceTarget,
    config: crate::V2Config,
    registry: ModuleRegistry,
    selected: ThreatModelRef,
    active: ThreatModelRef,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("note.md"),
            "Owned inert architecture example. Never executed.\n",
        )
        .unwrap();
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let config = crate::V2Config {
            model: Some(MODEL.into()),
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
        let import = |label: &str| {
            let result=registry.execute_tool("threat-model:import",json!({"activate":true,"label":label,
                "document":{"version":"1","methodology":"stride","systemContext":label,
                    "dfd":{"nodes":[{"id":"app","name":"Owned app","type":"process","trustZone":"internal","description":"Formats an inert greeting","purpose":"Explains the example"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}}}),&ctx).unwrap();
            serde_json::from_value(result["data"]["modelRef"].clone()).unwrap()
        };
        let selected = import("Selected accepted context");
        let active = import("Other active context");
        Self {
            root,
            workspace,
            config,
            registry,
            selected,
            active,
        }
    }
    fn ctx<'a>(
        &'a self,
        trace: Option<&'a crate::run_artifacts::TraceHandle>,
    ) -> ToolExecutionContext<'a> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace,
            cancellation: None,
            authorization: Default::default(),
        }
    }
    fn plan(&self, options: Value) -> crate::capabilities::campaign::ContextStudyReceipt {
        let mut input = json!({"threatModelRef":self.selected,"question":"What does app do?\nKeep uncertainty visible."});
        input
            .as_object_mut()
            .unwrap()
            .extend(options.as_object().unwrap().clone());
        let result=self.registry.execute_tool("campaign:context-study",json!({"campaignId":"question-one","investigationId":"questions","generationTool":TOOL,"contextInput":input}),&self.ctx(None)).unwrap();
        serde_json::from_value(result["data"].clone()).unwrap()
    }
    fn approve(&self, receipt: &crate::capabilities::campaign::ContextStudyReceipt) -> Value {
        let input = json!({"investigationId":"questions","expectedRevision":0,"model":MODEL,"maxProviderCalls":2,"protectedReviewCalls":1,
            "reason":"Explicit offline question test","campaignId":receipt.campaign_id,"campaignPlanSha256":receipt.plan_sha256,"campaignJobs":1,"maxJobAttempts":1});
        let ctx = self.ctx(None);
        let prepared = self
            .registry
            .prepare_dispatch_input("campaign:approve-allowance", input, &ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
        let allowance = receipt.load_allowance(self.root.path()).unwrap().unwrap();
        receipt.bound_input(&allowance).unwrap()
    }
    fn run(&self, input: Value, runtime: &OfflineQuestionRuntime) -> Result<Value> {
        let trace = crate::run_artifacts::TraceHandle::jsonl(
            self.root.path(),
            "question-one-context-001-a1",
        );
        let ctx = self.ctx(Some(&trace));
        let prepared = self
            .registry
            .prepare_dispatch_input(TOOL, input, &ctx, None)?
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(runtime))
    }
}

#[derive(Clone, Default)]
struct OfflineQuestionRuntime {
    binding: Option<crate::allowance::AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    drift: Option<std::path::PathBuf>,
    empty: bool,
}
impl AgentRuntime for OfflineQuestionRuntime {
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
            .context("Question requires shared admission")?;
        let reservation = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reservation, crate::runtime::RuntimeCostReport::UNAVAILABLE)?;
        if let Some(path) = &self.drift {
            fs::write(path, "Changed inert context source\n")?;
        }
        Ok(AgentQueryResponse {
            text: if self.empty {
                String::new()
            } else {
                "Synthetic answer: app formats a greeting [app].".into()
            },
            ..Default::default()
        })
    }
    fn triage_finding_blocking(&self, _: crate::TriageRequest) -> Result<crate::TriageOutcome> {
        unreachable!()
    }
}

#[test]
fn approved_question_uses_exact_context_and_preserves_active_context_and_review_reserve() {
    let fixture = Fixture::new();
    let receipt = fixture.plan(json!({}));
    let input = fixture.approve(&receipt);
    let runtime = OfflineQuestionRuntime::default();
    let before = fs::read(
        fixture
            .root
            .path()
            .join(".kuzushi/threat-models/manifest.json"),
    )
    .unwrap();
    let result = fixture.run(input, &runtime).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["contextRef"], json!(fixture.selected));
    assert_eq!(result["data"]["findingDecisionApplied"], false);
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].prompt.contains("Other active context"));
    assert!(requests[0].prompt.contains("Selected accepted context"));
    assert_eq!(requests[0].tool_policy.tools.len(), 0);
    assert_eq!(
        fs::read(
            fixture
                .root
                .path()
                .join(".kuzushi/threat-models/manifest.json")
        )
        .unwrap(),
        before
    );
    assert_eq!(
        load_active_threat_model(fixture.root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        fixture.active
    );
    let snapshot = receipt
        .load_allowance(fixture.root.path())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.committed_calls, 1);
    assert_eq!(snapshot.protected_review_remaining(), 1);
}

#[test]
fn source_drift_before_dispatch_blocks_without_querying() {
    let fixture = Fixture::new();
    let receipt = fixture.plan(json!({}));
    let input = fixture.approve(&receipt);
    fs::write(fixture.root.path().join("note.md"), "Changed source\n").unwrap();
    let runtime = OfflineQuestionRuntime::default();
    assert!(fixture.run(input, &runtime).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn source_drift_during_question_retains_partial_answer_and_spending() {
    let fixture = Fixture::new();
    let receipt = fixture.plan(json!({}));
    let input = fixture.approve(&receipt);
    let runtime = OfflineQuestionRuntime {
        drift: Some(fixture.root.path().join("note.md")),
        ..Default::default()
    };
    let result = fixture.run(input, &runtime).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(result["data"]["answer"]
        .as_str()
        .unwrap()
        .contains("Synthetic answer"));
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
fn empty_answer_is_failed_without_a_repair_request() {
    let fixture = Fixture::new();
    let receipt = fixture.plan(json!({}));
    let input = fixture.approve(&receipt);
    let runtime = OfflineQuestionRuntime {
        empty: true,
        ..Default::default()
    };
    assert!(fixture.run(input, &runtime).is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn question_cannot_use_an_allowance_without_a_frozen_job() {
    let fixture = Fixture::new();
    let ctx = fixture.ctx(None);
    let input = json!({"investigationId":"legacy-question","expectedRevision":0,"model":MODEL,
        "maxProviderCalls":2,"protectedReviewCalls":1,"reason":"Explicit offline standalone allowance"});
    let prepared = fixture
        .registry
        .prepare_dispatch_input("campaign:approve-allowance", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let runtime = OfflineQuestionRuntime::default();
    let result=fixture.run(json!({"question":"What does app do?","threatModelRef":fixture.selected,
        "allowanceRef":{"schemaVersion":1,"investigationId":"legacy-question","revision":1,"workId":"unplanned-question"}}),&runtime);
    let error = result.unwrap_err();
    assert!(error.to_string().contains("require an approved fixed job"), "{error:#}");
    assert_eq!(crate::runtime::runtime_failure_metadata(&error).unwrap().error_class,
        crate::RuntimeFailureClass::AllowanceRefused);
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn oversized_notes_refuse_plan_preparation_without_model_work() {
    let fixture = Fixture::new();
    let runtime = OfflineQuestionRuntime::default();
    let ctx = fixture.ctx(None);
    let result=fixture.registry.execute_tool("campaign:context-study",json!({"campaignId":"oversized-question",
        "generationTool":TOOL,"contextInput":{"question":"Explain app","threatModelRef":fixture.selected,
            "operatorContext":"x".repeat(65537)}}),&ctx);
    assert!(result.is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert!(!fixture
        .root
        .path()
        .join(".kuzushi/v3/campaigns/oversized-question/plan.json")
        .exists());
}

fn save_question_result(fixture: &Fixture, result: &Value, state: &str) {
    let path = crate::run_artifact_path(fixture.root.path(), "question-result", "result.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec(result).unwrap()).unwrap();
    let queue = fixture
        .root
        .path()
        .join(".kuzushi/v3/campaigns/question-one/queue.json");
    fs::write(
        queue,
        json!({"jobs":{"context-001":{"state":state,"runId":"question-result","attempts":1}}})
            .to_string(),
    )
    .unwrap();
}

#[test]
fn saved_question_recovery_checks_frozen_identity_and_preserves_partial_answers() {
    let fixture = Fixture::new();
    let receipt = fixture.plan(json!({}));
    assert!(receipt
        .question_answer(fixture.root.path())
        .unwrap()
        .is_none());
    let input = fixture.approve(&receipt);
    let result = fixture
        .run(input, &OfflineQuestionRuntime::default())
        .unwrap();
    save_question_result(&fixture, &result, "completed");
    let answer = receipt
        .question_answer(fixture.root.path())
        .unwrap()
        .unwrap();
    assert_eq!(answer.context_ref, fixture.selected);
    assert_eq!(answer.source_identity, receipt.source_identity);
    assert!(!answer.partial);
    for state in ["failed", "interrupted", "parked", "unrecognized"] {
        save_question_result(&fixture, &result, state);
        assert!(
            receipt.question_answer(fixture.root.path()).is_err(),
            "{state}"
        );
    }
    for (pointer, replacement) in [
        ("/data/model", json!("other-model")),
        ("/data/question", json!("different question")),
        ("/data/contextRef", json!(fixture.active)),
        ("/data/schemaVersion", json!(2)),
        ("/data/answer", json!("")),
        ("/status", json!("failed")),
    ] {
        let mut changed = result.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        save_question_result(&fixture, &changed, "completed");
        assert!(
            receipt.question_answer(fixture.root.path()).is_err(),
            "{pointer}"
        );
    }
    let mut partial = result;
    partial["status"] = json!("partial");
    save_question_result(&fixture, &partial, "partial");
    assert!(
        receipt
            .question_answer(fixture.root.path())
            .unwrap()
            .unwrap()
            .partial
    );
}

#[test]
fn approved_question_cannot_complete_map() {
    let fixture = Fixture::new();
    let receipt = fixture.plan(json!({}));
    fixture.approve(&receipt);
    let error = fixture
        .registry
        .execute_tool(
            "campaign:context-map",
            json!({"campaignId":receipt.campaign_id,
        "expectedPlanSha256":receipt.plan_sha256}),
            &fixture.ctx(None),
        )
        .unwrap_err();
    assert!(error.to_string().contains("cannot complete Map"));
    assert_eq!(
        crate::workflow_attempts::load_phase_attempt_ledger(fixture.root.path())
            .unwrap()
            .attempts()
            .count(),
        0
    );
}
