use crate::allowance::{AllowanceBinding, InvestigationWork};
use crate::findings::FindingStore;
use crate::runtime::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, RuntimeCost, RuntimeCostReport,
};
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(super) struct ObservationRuntime {
    binding: Option<AllowanceBinding>,
    pub requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    pub response: Value,
    pub cancel: Option<crate::scan::ScanCancellation>,
    pub change_source: Option<std::path::PathBuf>,
}

impl AgentRuntime for ObservationRuntime {
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
        self.requests.lock().unwrap().push(request);
        binding.settle(reservation, RuntimeCostReport::known(RuntimeCost::ZERO))?;
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        if let Some(path) = &self.change_source {
            std::fs::write(
                path,
                "Owned source changed during response. Never executed.\n",
            )?;
        }
        Ok(AgentQueryResponse {
            structured: Some(self.response.clone()),
            cost_usd_reported: true,
            ..Default::default()
        })
    }
    fn triage_finding_blocking(
        &self,
        _: crate::runtime::TriageRequest,
    ) -> anyhow::Result<crate::findings::TriageOutcome> {
        anyhow::bail!("Owned advisory observation test forbids triage")
    }
}

pub(super) fn pattern() -> Value {
    json!({"fixShape":"Owned changed greeting marker","vulnerableShape":"Owned prior greeting marker","description":"Labeled inert pattern. No defect is claimed."})
}

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub workspace: WorkspaceTarget,
    pub store: FindingStore,
    config: V2Config,
    pub runtime: ObservationRuntime,
    pub cancel: crate::scan::ScanCancellation,
}

impl Fixture {
    pub fn new(calls: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("hello.txt"),
            "Owned greeting text. Never executed.\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let fixture = Self {
            _root: root,
            workspace,
            store,
            config: V2Config {
                model: Some("openai:gpt-5.5".into()),
                ..Default::default()
            },
            runtime: ObservationRuntime {
                binding: None,
                requests: Default::default(),
                response: json!({"variants":[]}),
                cancel: None,
                change_source: None,
            },
            cancel: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = fixture.context();
        let prepared=registry.prepare_dispatch_input("campaign:approve-allowance",json!({"investigationId":"owned-advisory-search","expectedRevision":0,"model":fixture.config.model,"maxProviderCalls":calls,"protectedReviewCalls":1,"reason":"Owned advisory observation contract"}),&ctx,None).unwrap().authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
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
    pub fn dispatch(&self, extra: Value) -> anyhow::Result<Value> {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.context();
        let mut input = json!({"pattern":pattern(),"advisoryId":"OWNED-GREETING","allowanceRef":{"schemaVersion":1,"investigationId":"owned-advisory-search","revision":1,"workId":"search-1"}});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let prepared = registry
            .prepare_dispatch_input("ndiff:hunt-variants", input, &ctx, None)?
            .authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&self.runtime))
    }
}
