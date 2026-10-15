use crate::allowance::{AllowanceBinding, InvestigationWork};
use crate::runtime::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, RuntimeCost, RuntimeCostReport,
};
use crate::{FindingStore, ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(super) struct CatalogRuntime {
    binding: Option<AllowanceBinding>,
    pub requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    pub response: Value,
    pub cancellation: Option<(crate::scan::ScanCancellation, usize)>,
}
impl AgentRuntime for CatalogRuntime {
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
        assert_eq!(binding.work().work, InvestigationWork::Learning);
        let reservation = binding.reserve(&request.model)?;
        let mut requests = self.requests.lock().unwrap();
        requests.push(request);
        binding.settle(reservation, RuntimeCostReport::known(RuntimeCost::ZERO))?;
        if let Some((cancel, count)) = &self.cancellation {
            if requests.len() == *count {
                cancel.cancel();
            }
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
        anyhow::bail!("Owned catalog forbids triage")
    }
}
pub(super) fn record(id: &str) -> Value {
    json!({"id":id,"source":"claimed-source","description":"Labeled owned advisory; no defect claimed","cwes":["CWE-79"],"affected":[],"patches":[{"url":"https://example.invalid/owned.diff","kind":"diff"}],"raw":{}})
}

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub workspace: WorkspaceTarget,
    pub store: FindingStore,
    pub config: V2Config,
    pub runtime: CatalogRuntime,
    pub cancel: crate::scan::ScanCancellation,
}
impl Fixture {
    pub fn new(calls: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("hello.txt"),
            "Owned inert greeting. Never executed.\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("package.json"),
            r#"{"name":"owned-app","dependencies":{"owned-lib":"1.0.0"}}"#,
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
            runtime: CatalogRuntime {
                binding: None,
                requests: Default::default(),
                response: json!({"fixShape":"Owned changed greeting marker","vulnerableShape":"Owned prior greeting marker","description":"Labeled inert pattern. No defect claimed.","cwe":["CWE-79"],"languages":["text"],"keywords":["owned"]}),
                cancellation: None,
            },
            cancel: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = fixture.context();
        let prepared=registry.prepare_dispatch_input("campaign:approve-allowance",json!({"investigationId":"owned-catalog","expectedRevision":0,"model":"openai:gpt-5.5","maxProviderCalls":calls,"protectedReviewCalls":1,"reason":"Owned catalog contract"}),&ctx,None).unwrap().authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
            .unwrap();
        fixture
    }
    pub fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: Some(&self.cancel),
            authorization: Default::default(),
        }
    }
    pub fn input(&self) -> Value {
        json!({"cves":["OWNED-ONE"],"offline":true,"regressionGate":false,"fixtures":{"OWNED-ONE":record("OWNED-ONE"),"OWNED-TWO":record("OWNED-TWO")},"patchFixtures":{"https://example.invalid/owned.diff":"--- a/hello.txt\n+++ b/hello.txt\n-Owned greeting\n+Owned changed greeting\n"},"allowanceRef":{"schemaVersion":1,"investigationId":"owned-catalog","revision":1,"workId":"draft"}})
    }
    pub fn dispatch(&self, tool: &str, extra: Value) -> anyhow::Result<Value> {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.context();
        let mut input = self.input();
        if tool == "threat-intel:research" {
            input.as_object_mut().unwrap().remove("cves");
        }
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let prepared = registry
            .prepare_dispatch_input(tool, input, &ctx, None)?
            .authorize_explicit_headless();
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&self.runtime))
    }
}
