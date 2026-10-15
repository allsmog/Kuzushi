use crate::allowance::{AllowanceBinding, InvestigationWork};
use crate::runtime::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, RuntimeCost, RuntimeCostReport,
};
use crate::{FindingStore, ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(super) struct PatternRuntime {
    pub binding: Option<AllowanceBinding>,
    pub requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    pub response: Value,
    pub cancel: Option<crate::scan::ScanCancellation>,
}

impl AgentRuntime for PatternRuntime {
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
        let discovery = request.system_prompt.contains("N-day variant hunter");
        let binding = self.binding.as_ref().unwrap();
        assert_eq!(
            binding.work().work,
            if discovery {
                InvestigationWork::Discovery
            } else {
                InvestigationWork::Learning
            }
        );
        let reservation = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        binding.settle(reservation, RuntimeCostReport::known(RuntimeCost::ZERO))?;
        if let Some(cancel) = &self.cancel {
            cancel.cancel();
        }
        Ok(AgentQueryResponse {
            structured: Some(if discovery {
                json!({"variants":[]})
            } else {
                self.response.clone()
            }),
            cost_usd_reported: true,
            ..Default::default()
        })
    }
    fn triage_finding_blocking(
        &self,
        _: crate::runtime::TriageRequest,
    ) -> anyhow::Result<crate::findings::TriageOutcome> {
        anyhow::bail!("Owned advisory draft forbids triage")
    }
}

pub(super) fn pattern() -> Value {
    json!({"fixShape":"Owned changed greeting marker","vulnerableShape":"Owned prior greeting marker","description":"Labeled inert draft. No defect is claimed."})
}

pub(super) struct Fixture {
    _root: tempfile::TempDir,
    pub workspace: WorkspaceTarget,
    pub store: FindingStore,
    config: V2Config,
    pub runtime: PatternRuntime,
    pub cancel: crate::scan::ScanCancellation,
}

impl Fixture {
    pub fn new(calls: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("hello.txt"),
            "Owned greeting. Never executed.\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("owned.diff"),
            "--- a/hello.txt\n+++ b/hello.txt\n-Owned greeting\n+Owned changed greeting\n",
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
            runtime: PatternRuntime {
                binding: None,
                requests: Default::default(),
                response: pattern(),
                cancel: None,
            },
            cancel: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = fixture.context();
        let prepared=registry.prepare_dispatch_input("campaign:approve-allowance",json!({"investigationId":"owned-advisory-pattern","expectedRevision":0,"model":fixture.config.model,"maxProviderCalls":calls,"protectedReviewCalls":1,"reason":"Owned advisory pattern contract"}),&ctx,None).unwrap().authorize_explicit_headless();
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
    pub fn dispatch(&self, extra: Value) -> anyhow::Result<Value> {
        self.dispatch_tool("ndiff:extract-fix-pattern", extra, true)
    }
    pub fn dispatch_tool(
        &self,
        tool: &str,
        extra: Value,
        authorize: bool,
    ) -> anyhow::Result<Value> {
        let registry = ModuleRegistry::with_v2_builtins();
        let ctx = self.context();
        let mut input = json!({"allowanceRef":{"schemaVersion":1,"investigationId":"owned-advisory-pattern","revision":1,"workId":"draft-1"}});
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let mut prepared = registry.prepare_dispatch_input(tool, input, &ctx, None)?;
        if authorize {
            prepared = prepared.authorize_explicit_headless();
        }
        registry.dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&self.runtime))
    }
}
