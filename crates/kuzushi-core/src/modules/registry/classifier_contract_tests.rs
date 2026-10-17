use crate::allowance::InvestigationWork;
use crate::findings::test_support::ReviewedFindingFixture;
use crate::findings::{ReviewDecisionVerdict, TriageOutcome};
use crate::modules::{phase_result_phase, AllowanceCategory, ModuleMaturity};
use crate::runtime::scripted_fixture::account_scripted_runtime;
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
use crate::{ModuleRegistry, ToolExecutionContext, V2Config};
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct ClassifierFixtureRuntime {
    response: Value,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
}

impl AgentRuntime for ClassifierFixtureRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.requests.lock().unwrap().push(request);
        Ok(AgentQueryResponse {
            structured: Some(self.response.clone()),
            cost_usd_reported: true,
            ..Default::default()
        })
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        anyhow::bail!("Classifier cannot start further review")
    }
}

struct ClassifierFixture {
    subject: ReviewedFindingFixture,
    config: V2Config,
    runtime: ClassifierFixtureRuntime,
}

impl ClassifierFixture {
    fn new(response: Value) -> Self {
        Self {
            subject: ReviewedFindingFixture::new(),
            config: V2Config {
                model: Some("openai:gpt-4.1".into()),
                ..Default::default()
            },
            runtime: ClassifierFixtureRuntime {
                response,
                requests: Default::default(),
            },
        }
    }
    fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.subject.workspace),
            findings_store: Some(&self.subject.store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }
    fn score(&self, percentile: f64, calls: u32) -> Result<Value> {
        let ctx = self.context();
        let runtime =
            account_scripted_runtime(&ctx, &self.runtime, InvestigationWork::Review, calls);
        ModuleRegistry::with_v2_builtins_without_optional_adapters().execute_tool_with_runtime(
            "classifier-gate:score", json!({"findingFingerprint":self.subject.finding().fingerprint,"targetPercentile":percentile}), &ctx, Some(&runtime))
    }
}

#[test]
fn classifier_is_auxiliary_labs_review_not_a_completed_review() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let tool = registry.resolve_tool("classifier-gate:score").unwrap();
    assert_eq!(phase_result_phase(tool), None);
    assert!(!tool.phase_result);
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
    assert_eq!(tool.allowance_category, Some(AllowanceCategory::Review));
}

#[test]
fn empty_response_stays_partial_and_preserves_human_authority() {
    let fixture = ClassifierFixture::new(json!({}));
    fixture
        .subject
        .record_human_decision(ReviewDecisionVerdict::RejectedFalsePositive);
    let before = fixture.subject.store.list_all_review_decisions().unwrap();
    let result = fixture.score(0.8, 1).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(result["data"]["score"].is_null());
    assert_eq!(result["data"]["samplesSeen"], 0);
    assert_eq!(result["data"]["followupStarted"], false);
    assert_eq!(
        fixture
            .subject
            .store
            .list_all_review_decisions()
            .unwrap()
            .len(),
        before.len()
    );
    assert_eq!(
        fixture
            .subject
            .store
            .latest_review_decision(fixture.subject.finding().id.unwrap())
            .unwrap()
            .unwrap()
            .decision
            .verdict,
        ReviewDecisionVerdict::RejectedFalsePositive
    );
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn explicit_zero_retains_the_human_decision_without_scheduling_work() {
    let fixture = ClassifierFixture::new(json!({"likely":true,"score":0.0}));
    fixture
        .subject
        .record_human_decision(ReviewDecisionVerdict::RejectedFalsePositive);
    let result = fixture.score(0.8, 1).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["score"], 0.0);
    assert_eq!(result["data"]["shouldDeepAudit"], false);
    assert_eq!(result["data"]["modelOpinionOnly"], true);
    assert_eq!(result["data"]["samplesSeen"], 1);
    assert_eq!(
        fixture
            .subject
            .store
            .list_all_review_decisions()
            .unwrap()
            .len(),
        1
    );
    assert!(fixture.subject.finding().triage.is_none());
    assert!(!fixture
        .subject
        .workspace
        .root()
        .join(".kuzushi/v3/campaigns")
        .exists());
}

#[test]
fn invalid_percentile_and_exhausted_allowance_never_query() {
    let fixture = ClassifierFixture::new(json!({"score":0.5}));
    for p in [0.0, 1.0, -0.5, 1.5] {
        assert!(fixture
            .score(p, 1)
            .unwrap_err()
            .to_string()
            .contains("targetPercentile"));
    }
    assert!(fixture.score(0.8, 0).is_err());
    assert!(fixture.runtime.requests.lock().unwrap().is_empty());
    assert!(fixture
        .subject
        .store
        .list_all_review_decisions()
        .unwrap()
        .is_empty());
}

#[test]
fn score_hint_keeps_the_named_percentile_after_previous_history() {
    let fixture = ClassifierFixture::new(json!({"score":0.4}));
    let first = fixture.score(0.8, 1).unwrap();
    let second = fixture.score(0.9, 1).unwrap();
    let third = fixture.score(0.8, 1).unwrap();
    assert_eq!(first["data"]["samplesSeen"], 1);
    assert_eq!(second["data"]["samplesSeen"], 1);
    assert_eq!(third["data"]["samplesSeen"], 2);
    assert_eq!(second["data"]["thresholdScope"], "workspace-history");
    assert_eq!(fixture.runtime.requests.lock().unwrap().len(), 3);
}

#[test]
fn metadata_score_cannot_replace_an_existing_automatic_review_opinion() {
    let fixture = ClassifierFixture::new(json!({"score":0.1}));
    fixture
        .subject
        .record_auto_triage(crate::findings::TriageVerdict::TruePositive);
    let before = fixture.subject.store.list_all_review_decisions().unwrap();
    let result = fixture.score(0.8, 1).unwrap();
    assert_eq!(result["data"]["findingDecisionChanged"], false);
    assert_eq!(
        fixture.subject.finding().triage.unwrap().verdict,
        crate::findings::TriageVerdict::TruePositive
    );
    assert_eq!(
        fixture
            .subject
            .store
            .list_all_review_decisions()
            .unwrap()
            .len(),
        before.len()
    );
}
