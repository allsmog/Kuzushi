use crate::allowance::{AllowanceBinding, InvestigationWork};
use crate::findings::test_support::ReviewedFindingFixture;
use crate::findings::{ReviewDecisionVerdict, TriageOutcome};
use crate::modules::{ModuleMaturity, ToolPhase};
use crate::runtime::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, RuntimeCost, RuntimeCostReport,
    TriageRequest,
};
use crate::scan::ScanCancellation;
use crate::{ModuleRegistry, ToolExecutionContext, V2Config};
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct ObservationRuntime {
    binding: Option<AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    response: Value,
    cancel_after_response: Option<ScanCancellation>,
}

impl AgentRuntime for ObservationRuntime {
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
        assert_eq!(binding.work().work, InvestigationWork::Discovery);
        let reservation = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reservation, RuntimeCostReport::known(RuntimeCost::ZERO))?;
        if let Some(cancel) = &self.cancel_after_response {
            cancel.cancel();
        }
        Ok(AgentQueryResponse {
            structured: Some(self.response.clone()),
            cost_usd_reported: true,
            ..Default::default()
        })
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        anyhow::bail!("Owned observation test forbids triage")
    }
}

struct ObservationFixture {
    subject: ReviewedFindingFixture,
    config: V2Config,
    runtime: ObservationRuntime,
    cancellation: ScanCancellation,
}

impl ObservationFixture {
    fn new(response: Value, calls: u64) -> Self {
        let subject = ReviewedFindingFixture::new();
        subject.record_human_decision(ReviewDecisionVerdict::Confirmed);
        let fixture = Self {
            subject,
            config: V2Config {
                model: Some("openai:gpt-4.1".into()),
                ..Default::default()
            },
            runtime: ObservationRuntime {
                binding: None,
                requests: Default::default(),
                response,
                cancel_after_response: None,
            },
            cancellation: ScanCancellation::default(),
        };
        fixture.approve(calls);
        fixture
    }

    fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.subject.workspace),
            findings_store: Some(&self.subject.store),
            trace: None,
            cancellation: Some(&self.cancellation),
            authorization: Default::default(),
        }
    }

    fn approve(&self, calls: u64) {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.context();
        let input=registry.prepare_dispatch_input("campaign:approve-allowance",json!({
            "investigationId":"owned-observation","expectedRevision":0,"model":"openai:gpt-4.1",
            "maxProviderCalls":calls,"protectedReviewCalls":1,"reason":"Owned no-network observation test"}),&ctx,None)
            .unwrap().authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(input, &ctx, None)
            .unwrap();
    }

    fn dispatch(&self, extra: Value) -> Result<Value> {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.context();
        let mut input = json!({"fingerprint":"F-0001","includeVendored":false,
            "allowanceRef":{"schemaVersion":1,"investigationId":"owned-observation","revision":1,"workId":"search-1"}});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let prepared = registry
            .prepare_dispatch_input("variant:hunt", input, &ctx, None)?
            .authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&self.runtime))
    }

    fn query_count(&self) -> usize {
        self.runtime.requests.lock().unwrap().len()
    }
}

fn observation() -> Value {
    json!({"variants":[{"filePath":"greeting.txt","startLine":1,"severity":"INFO",
        "confidence":"MEDIUM","message":"Labeled owned observation. No defect is claimed."}]})
}

#[test]
fn related_search_is_experimental_and_cannot_complete_scan() {
    let registry = ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("variant:hunt").unwrap();
    assert_eq!(tool.phase, ToolPhase::Scan);
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
    assert!(!tool.phase_result);
    assert!(!registry.tool_is_discoverable(&tool.name));
    assert!(registry
        .prepare_tool_input(
            &tool.name,
            json!({"fingerprint":"owned","scanContextRef":{}}),
            None
        )
        .is_err());
    assert!(registry
        .prepare_tool_input(
            &tool.name,
            json!({"fingerprint":"owned","thinking_level":"maximum"}),
            None
        )
        .is_err());
}

#[test]
fn related_observations_are_imported_without_inheriting_original_confirmation() {
    let fixture = ObservationFixture::new(observation(), 3);
    let before = fixture.subject.store.list_all_review_decisions().unwrap();
    let result = fixture.dispatch(json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["coverage"]["complete"], false);
    assert_eq!(result["data"]["coverage"]["sourceRevisionVerified"], false);
    assert_eq!(fixture.query_count(), 1);
    assert_eq!(
        fixture.runtime.requests.lock().unwrap()[0].thinking_level,
        None
    );
    assert_eq!(
        fixture.subject.store.list_all_review_decisions().unwrap(),
        before
    );
    let findings = fixture.subject.store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 2);
    let related = findings
        .iter()
        .find(|finding| finding.tool == "variant-analysis")
        .unwrap();
    assert!(matches!(
        crate::findings::load_finding_review_gate(&fixture.subject.store, related).unwrap(),
        crate::findings::FindingReviewGate::Unreviewed
    ));
}

#[test]
fn empty_explicit_observations_leave_the_confirmed_subject_intact() {
    let fixture = ObservationFixture::new(json!({"variants":[]}), 3);
    let result = fixture.dispatch(json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["variants"], json!([]));
    assert_eq!(fixture.subject.store.list_all_findings().unwrap().len(), 1);
    assert!(matches!(
        crate::findings::load_finding_review_gate(
            &fixture.subject.store,
            &fixture.subject.finding()
        )
        .unwrap(),
        crate::findings::FindingReviewGate::Confirmed(_)
    ));
}

#[test]
fn invalid_output_spends_only_the_allowed_repair_and_imports_nothing() {
    let fixture = ObservationFixture::new(json!({}), 3);
    let error = fixture.dispatch(json!({})).unwrap_err();
    assert!(format!("{error:#}").contains("after one repair"));
    assert_eq!(fixture.query_count(), 2);
    assert_eq!(fixture.subject.store.list_all_findings().unwrap().len(), 1);
}

#[test]
fn explicit_prepared_reasoning_reaches_the_query() {
    let fixture = ObservationFixture::new(json!({"variants":[]}), 3);
    fixture.dispatch(json!({"thinking_level":"low"})).unwrap();
    assert_eq!(
        fixture.runtime.requests.lock().unwrap()[0]
            .thinking_level
            .as_deref(),
        Some("low")
    );
}

#[test]
fn canceled_before_execution_starts_no_query_or_observation() {
    let fixture = ObservationFixture::new(observation(), 3);
    fixture.cancellation.cancel();
    assert!(fixture.dispatch(json!({})).is_err());
    assert_eq!(fixture.query_count(), 0);
    assert_eq!(fixture.subject.store.list_all_findings().unwrap().len(), 1);
}

#[test]
fn canceled_after_a_response_does_not_import_observations() {
    let mut fixture = ObservationFixture::new(observation(), 3);
    fixture.runtime.cancel_after_response = Some(fixture.cancellation.clone());
    assert!(fixture.dispatch(json!({})).is_err());
    assert_eq!(fixture.query_count(), 1);
    assert_eq!(fixture.subject.store.list_all_findings().unwrap().len(), 1);
}

#[test]
fn discovery_cannot_borrow_the_protected_review_call() {
    let fixture = ObservationFixture::new(observation(), 1);
    assert!(fixture.dispatch(json!({})).is_err());
    assert_eq!(fixture.query_count(), 0);
}
