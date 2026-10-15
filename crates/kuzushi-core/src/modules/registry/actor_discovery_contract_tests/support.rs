use crate::allowance::{AllowanceBinding, InvestigationWork};
use crate::runtime::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, RuntimeCost, RuntimeCostReport,
};
use crate::{FindingStore, ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(super) struct ActorRuntime {
    binding: Option<AllowanceBinding>,
    pub requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    pub canceled_response: Option<crate::scan::ScanCancellation>,
    pub truncated_first: bool,
}

impl AgentRuntime for ActorRuntime {
    fn allowance_binding(&self) -> Option<&AllowanceBinding> {
        self.binding.as_ref()
    }
    fn with_allowance_binding(
        &self,
        binding: AllowanceBinding,
    ) -> anyhow::Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(Self {
            binding: Some(binding),
            ..self.clone()
        }))
    }
    fn query_blocking(&self, request: AgentQueryRequest) -> anyhow::Result<AgentQueryResponse> {
        let binding = self.binding.as_ref().unwrap();
        assert_eq!(binding.work().work, InvestigationWork::Discovery);
        let reservation = binding.reserve(&request.model)?;
        let mut requests = self.requests.lock().unwrap();
        requests.push(request);
        let truncated = self.truncated_first && requests.len() == 1;
        binding.settle(reservation, RuntimeCostReport::known(RuntimeCost::ZERO))?;
        if let Some(cancel) = &self.canceled_response {
            cancel.cancel();
        }
        Ok(AgentQueryResponse {
            truncated,
            structured: Some(json!({"findings":[]})),
            cost_usd_reported: true,
            ..Default::default()
        })
    }
    fn triage_finding_blocking(
        &self,
        _: crate::runtime::TriageRequest,
    ) -> anyhow::Result<crate::findings::TriageOutcome> {
        anyhow::bail!("Owned actor fixture forbids triage")
    }
}

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub workspace: WorkspaceTarget,
    pub store: FindingStore,
    config: V2Config,
    pub runtime: ActorRuntime,
    pub cancel: crate::scan::ScanCancellation,
}

impl Fixture {
    pub fn new(calls: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("hello.rs"),"// Owned inert source. Never compiled or executed.\npub fn greeting() -> &'static str { \"Owned greeting\" }\n").unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        workspace.ensure_state_dir().unwrap();
        std::fs::write(crate::capabilities::persistent_threat_model_path(root.path()),serde_json::to_vec(&json!({
            "version":"1","methodology":"stride","dfd":{"nodes":[{"id":"reader","name":"Owned reader","type":"external-entity","trustZone":"external"}],"flows":[],"trustBoundaries":[]},"threats":[{"id":"owned-question","title":"Labeled source-review question; no defect is claimed","impact":"high","affectedNodeIds":["reader"],"affectedFiles":["hello.rs"]}],"summary":{}
        })).unwrap()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let fixture = Self {
            _root: root,
            workspace,
            store,
            config: V2Config {
                model: Some("openai:gpt-5.5".into()),
                ..Default::default()
            },
            runtime: ActorRuntime::default(),
            cancel: Default::default(),
        };
        fixture.approve(calls);
        fixture
    }
    fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: Some(&self.cancel),
            authorization: Default::default(),
        }
    }
    fn approve(&self, calls: u64) {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.context();
        let prepared=registry.prepare_dispatch_input("campaign:approve-allowance",json!({"investigationId":"owned-actor-query","expectedRevision":0,"model":self.config.model,"maxProviderCalls":calls,"protectedReviewCalls":1,"reason":"Owned actor query contract"}),&ctx,None).unwrap().authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
    }
    pub fn dispatch(&self, extra: Value) -> anyhow::Result<Value> {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.context();
        let mut input = json!({"maxActors":1,"runsPerActor":1,"allowanceRef":{"schemaVersion":1,"investigationId":"owned-actor-query","revision":1,"workId":"actor-1"}});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let prepared = registry
            .prepare_dispatch_input("offense-review:threat-hunt", input, &ctx, None)?
            .authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&self.runtime))
    }
}
