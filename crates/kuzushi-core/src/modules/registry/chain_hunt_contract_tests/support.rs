use crate::allowance::{AllowanceBinding, InvestigationWork};
use crate::findings::{
    Finding, FindingStore, ReviewDecision, ReviewDecisionVerdict, TriageAuthor, TriageOutcome,
};
use crate::runtime::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, RuntimeCost, RuntimeCostReport,
    TriageRequest,
};
use crate::scan::ScanCancellation;
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct HypothesisRuntime {
    binding: Option<AllowanceBinding>,
    pub requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    pub response: Value,
    pub cancel_after_response: Option<ScanCancellation>,
    pub dismiss_after_response: Option<(std::path::PathBuf, i64)>,
}

impl AgentRuntime for HypothesisRuntime {
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
        dismiss_subject(self.dismiss_after_response.as_ref())?;
        Ok(AgentQueryResponse {
            structured: Some(self.response.clone()),
            cost_usd_reported: true,
            ..Default::default()
        })
    }
    fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
        anyhow::bail!("Owned hypothesis test forbids triage")
    }
}

fn dismiss_subject(subject: Option<&(std::path::PathBuf, i64)>) -> Result<()> {
    let Some((path, id)) = subject else {
        return Ok(());
    };
    let store = FindingStore::open(path)?;
    store.append_user_review_decision(
        *id,
        &ReviewDecision {
            verdict: ReviewDecisionVerdict::RejectedFalsePositive,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: "Owned review changed during the query".into(),
            dismiss_reason: Some(crate::findings::DismissReason::FalsePositive),
            actor: Some("fixture operator".into()),
        },
    )?;
    Ok(())
}

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub workspace: WorkspaceTarget,
    pub store: FindingStore,
    config: V2Config,
    pub runtime: HypothesisRuntime,
    pub cancellation: ScanCancellation,
}

impl Fixture {
    pub fn new(calls: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        append_owned_finding(&store, &workspace, "first", true);
        append_owned_finding(&store, &workspace, "second", true);
        let members = store
            .list_all_findings()
            .unwrap()
            .into_iter()
            .map(|f| f.fingerprint)
            .collect::<Vec<_>>();
        let fixture = Self {
            _root: root,
            workspace,
            store,
            config: V2Config {
                model: Some("openai:gpt-4.1".into()),
                ..Default::default()
            },
            runtime: HypothesisRuntime {
                response: proposal(members),
                ..Default::default()
            },
            cancellation: ScanCancellation::default(),
        };
        fixture.approve(calls);
        fixture
    }
    pub fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: Some(&self.cancellation),
            authorization: Default::default(),
        }
    }
    fn approve(&self, calls: u64) {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.context();
        let prepared=registry.prepare_dispatch_input("campaign:approve-allowance",json!({"investigationId":"owned-hypotheses",
            "expectedRevision":0,"model":"openai:gpt-4.1","maxProviderCalls":calls,"protectedReviewCalls":1,
            "reason":"Owned metadata-only hypothesis regression"}),&ctx,None).unwrap().authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
    }
    pub fn dispatch(&self, extra: Value) -> Result<Value> {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.context();
        let mut input = json!({"allowanceRef":{"schemaVersion":1,"investigationId":"owned-hypotheses","revision":1,"workId":"hypotheses-1"}});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let prepared = registry
            .prepare_dispatch_input("triage:chain-hunt", input, &ctx, None)?
            .authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&self.runtime))
    }
    pub fn query_count(&self) -> usize {
        self.runtime.requests.lock().unwrap().len()
    }
}

pub(super) fn proposal(members: Vec<String>) -> Value {
    json!({"chains":[{"title":"Labeled owned relationship hypothesis","members":members,
        "attack_path":["Which source evidence supports an interaction between the owned greetings?"],
        "cumulative_impact":"Unverified metadata association. No defect is claimed.",
        "why_this_chain_matters":"Owned transport fixture only.","detection_difficulty":"Unknown without independent source review."}]})
}

pub(super) fn append_owned_finding(
    store: &FindingStore,
    workspace: &WorkspaceTarget,
    name: &str,
    confirmed: bool,
) -> i64 {
    let run = format!("owned-{name}");
    store
        .record_run_started(&run, workspace.root(), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "owned-metadata",
        format!("owned.{name}"),
        format!("{name}.txt"),
        1,
        None,
        crate::findings::Severity::Info,
        format!("Labeled owned {name} greeting. No defect is claimed."),
    );
    let id = store.insert_finding(&run, &finding).unwrap();
    store.record_run_finished(&run, "completed", 1).unwrap();
    if confirmed {
        confirm(store, id);
    }
    id
}

pub(super) fn confirm(store: &FindingStore, id: i64) {
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Synthetic acceptance solely for relationship UI testing".into(),
                dismiss_reason: None,
                actor: Some("fixture operator".into()),
            },
        )
        .unwrap();
}
