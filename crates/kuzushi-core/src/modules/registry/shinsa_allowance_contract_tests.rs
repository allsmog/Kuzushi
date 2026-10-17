use super::*;
use crate::allowance::{AllowanceBinding, AllowanceWork, InvestigationWork};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse};
use std::sync::{Arc, Mutex};

const MODEL: &str = "openai-codex:gpt-5.5";
const ACTIONS: &[&str] = &[
    "shinsa:scan",
    "shinsa:quick-check",
    "shinsa:nist-scan",
    "shinsa:nist-quick-check",
];

struct Fixture {
    root: tempfile::TempDir,
    workspace: crate::WorkspaceTarget,
    config: crate::V2Config,
    registry: ModuleRegistry,
    store: crate::findings::FindingStore,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("policy.py"),
            "# Owned policy marker. Never executed.\n",
        )
        .unwrap();
        std::fs::create_dir(root.path().join("owned-plugin")).unwrap();
        let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
        let store = crate::findings::FindingStore::open(workspace.findings_db_path()).unwrap();
        Self {
            workspace,
            store,
            root,
            config: crate::V2Config {
                model: Some(MODEL.into()),
                ..Default::default()
            },
            registry: ModuleRegistry::with_v2_builtins_without_optional_adapters(),
        }
    }

    fn ctx(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }

    fn input(&self) -> Value {
        json!({"pluginRoot": self.root.path().join("owned-plugin"), "outputDir":"owned-output"})
    }

    fn dispatch(
        &self,
        tool: &str,
        input: Value,
        runtime: Option<&dyn AgentRuntime>,
    ) -> Result<Value> {
        let ctx = self.ctx();
        let prepared = self
            .registry
            .prepare_dispatch_input(tool, input, &ctx, None)?
            .authorize_explicit_headless();
        self.registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, runtime)
    }

    fn approve(&self) {
        self.dispatch(
            "campaign:approve-allowance",
            json!({
                "investigationId":"owned-compliance", "expectedRevision":0,
                "model":MODEL, "maxProviderCalls":2, "protectedReviewCalls":1,
                "reason":"Owned intercepted compliance fixture; no provider transport"
            }),
            None,
        )
        .unwrap();
    }

    fn approved_input(&self) -> Value {
        let mut input = self.input();
        input["allowanceRef"] = json!({"schemaVersion":1,
            "investigationId":"owned-compliance", "revision":1, "workId":"owned-assessment"});
        input
    }

    fn ledger(&self) -> Arc<crate::SpendLimiter> {
        Arc::new(crate::SpendLimiter::open(self.workspace.findings_db_path()).unwrap())
    }
}

#[derive(Clone, Default)]
struct OfflineRuntime {
    binding: Option<AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    text: Option<&'static str>,
}

impl AgentRuntime for OfflineRuntime {
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
        let binding = self
            .binding
            .as_ref()
            .context("Unbudgeted fixture query reached")?;
        let reserved = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request.clone());
        let mut response = AgentQueryResponse {
            text: json!({"summary":"Owned policy review", "findings":[{
                "ruleId":"owned-policy", "filePath":"policy.py", "startLine":1,
                "severity":"info", "message":"Owned fixture policy marker needs an owner decision",
                "evidence":"policy.py:1"}],"controls":[],"maturity":{}})
            .to_string(),
            ..Default::default()
        };
        if let Some(text) = self.text {
            response.text = text.into();
        }
        binding.settle(reserved, response.checked_cost_report()?)?;
        Ok(response)
    }
    fn triage_finding_blocking(&self, _: crate::TriageRequest) -> Result<crate::TriageOutcome> {
        anyhow::bail!("This fixture performs no triage")
    }
}

#[test]
fn unbound_compliance_actions_refuse_before_requests_or_output() {
    for tool in ACTIONS {
        let f = Fixture::new();
        let runtime = OfflineRuntime::default();
        let error = f.dispatch(tool, f.input(), Some(&runtime)).unwrap_err();
        assert!(
            format!("{error:#}").contains("approved investigation allowance"),
            "{tool}: {error:#}"
        );
        assert!(runtime.requests.lock().unwrap().is_empty(), "{tool}");
        assert!(!f.root.path().join("owned-output").exists());
    }
}

#[test]
fn compliance_actions_declare_discovery_accounting_and_remain_experimental() {
    let f = Fixture::new();
    for name in ACTIONS {
        let descriptor = f.registry.resolve_tool(name).unwrap();
        assert_eq!(
            descriptor.allowance_category,
            Some(AllowanceCategory::Discovery)
        );
        assert!(descriptor
            .options
            .iter()
            .any(|option| option.name == "allowanceRef"));
        assert_eq!(descriptor.effect, ToolEffect::TargetWrite);
        assert_eq!(descriptor.approval, ApprovalPolicy::Explicit);
        assert!(!descriptor.phase_result);
    }
    let module = f
        .registry
        .all_modules()
        .find(|module| module.metadata().id == "shinsa")
        .unwrap();
    assert_eq!(module.maturity(), ModuleMaturity::Labs);
    assert!(
        !f.registry
            .resolve_tool("shinsa:frameworks")
            .unwrap()
            .phase_result
    );
}

#[test]
fn each_approved_compliance_mode_uses_one_call_and_protects_review() {
    for tool in ACTIONS {
        let f = Fixture::new();
        f.approve();
        let runtime = OfflineRuntime::default();
        let result = f
            .dispatch(tool, f.approved_input(), Some(&runtime))
            .unwrap();
        assert_eq!(result["status"], "completed", "{result}");
        assert_eq!(result["data"]["findings"].as_array().unwrap().len(), 1);
        assert_eq!(f.store.list_findings(10).unwrap().len(), 1);
        for field in ["statePath", "reportPath"] {
            assert!(std::path::Path::new(result["data"][field].as_str().unwrap()).is_file());
        }
        let requests = runtime.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].model, MODEL);
        assert!(requests[0]
            .prompt
            .contains("Owned policy marker. Never executed."));
        assert_eq!(requests[0].tool_policy.profile, "compliance-assessment");
        assert!(requests[0].tool_policy.tools.is_empty() && !requests[0].tool_policy.mcps);
        drop(requests);
        let ledger = f.ledger();
        let snapshot = ledger.allowance_snapshot("owned-compliance").unwrap();
        assert_eq!(snapshot.committed_calls, 1);
        assert_eq!(snapshot.protected_review_remaining(), 1);
        assert!(f
            .dispatch(tool, f.approved_input(), Some(&runtime))
            .is_err());
        assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn compliance_action_cannot_borrow_an_inherited_review_allowance() {
    let f = Fixture::new();
    f.approve();
    let binding = AllowanceBinding::new(
        f.ledger(),
        AllowanceWork {
            investigation_id: "owned-compliance".into(),
            revision: 1,
            run_id: "owned-parent-review".into(),
            work_id: "owned-review".into(),
            model: MODEL.into(),
            work: InvestigationWork::Review,
        },
    )
    .unwrap();
    let runtime = OfflineRuntime {
        binding: Some(binding),
        ..Default::default()
    };
    let error = f
        .dispatch(ACTIONS[0], f.input(), Some(&runtime))
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("Discovery investigation accounting")
            && format!("{error:#}").contains("parent Review allowance"),
        "{error:#}"
    );
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert!(!f.root.path().join("owned-output").exists());
}

#[test]
fn legacy_deep_audit_is_not_presented_as_an_equivalent_alias() {
    let f = Fixture::new();
    let module = f
        .registry
        .all_modules()
        .find(|module| module.metadata().id == "deep-audit")
        .unwrap();
    assert_eq!(module.maturity(), ModuleMaturity::Compatibility);
    let descriptor = f.registry.resolve_tool("deep-audit:run").unwrap();
    assert!(!descriptor.description.contains("alias"));
    assert!(descriptor.description.contains("campaign:review-study"));
    assert!(descriptor.hidden && module.is_hidden());
}

#[test]
fn malformed_assessment_spends_one_call_without_findings_or_reports() {
    let f = Fixture::new();
    f.approve();
    let runtime = OfflineRuntime {
        text: Some("not a structured assessment"),
        ..Default::default()
    };
    assert!(f
        .dispatch(ACTIONS[0], f.approved_input(), Some(&runtime))
        .is_err());
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(f.store.list_findings(10).unwrap().is_empty());
    assert!(!f
        .root
        .path()
        .join("owned-output/shinsa-state.json")
        .exists());
    assert!(!f
        .root
        .path()
        .join("owned-output/compliance-report.md")
        .exists());
    let snapshot = f.ledger().allowance_snapshot("owned-compliance").unwrap();
    assert_eq!(snapshot.committed_calls, 1);
    assert_eq!(snapshot.protected_review_remaining(), 1);
}

#[test]
fn missing_plugin_refuses_without_spending_approved_capacity() {
    let f = Fixture::new();
    f.approve();
    let runtime = OfflineRuntime::default();
    let mut input = f.approved_input();
    input["pluginRoot"] = json!(f.root.path().join("missing-plugin"));
    assert!(f.dispatch(ACTIONS[0], input, Some(&runtime)).is_err());
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert!(!f.root.path().join("owned-output").exists());
    assert_eq!(
        f.ledger()
            .allowance_snapshot("owned-compliance")
            .unwrap()
            .committed_calls,
        0
    );
}
