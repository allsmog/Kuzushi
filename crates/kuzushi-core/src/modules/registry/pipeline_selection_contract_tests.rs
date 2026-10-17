use super::*;
use crate::allowance::AllowanceBinding;
use crate::runtime::{AgentQueryRequest, AgentQueryResponse};
use std::sync::{Arc, Mutex};

const TOOL: &str = "pipeline:taint-cwe-select";
const MODEL: &str = "openai-codex:gpt-5.5";
const ANSWER: &str =
    r#"{"cwes":[{"id":"CWE-20","name":"Input validation","reason":"Owned source marker"}]}"#;

struct Fixture {
    root: tempfile::TempDir,
    workspace: crate::WorkspaceTarget,
    registry: ModuleRegistry,
    config: crate::V2Config,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("owned.py"),
            "# Owned source marker; never executed.\n",
        )
        .unwrap();
        Self {
            workspace: crate::WorkspaceTarget::new(root.path()).unwrap(),
            root,
            registry: ModuleRegistry::with_v2_builtins_without_optional_adapters(),
            config: crate::V2Config {
                model: Some(MODEL.into()),
                ..Default::default()
            },
        }
    }

    fn ctx(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
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
                "investigationId":"owned-selection", "expectedRevision":0, "model":MODEL,
                "maxProviderCalls":2, "protectedReviewCalls":1,
                "reason":"One inert source-class selection; no provider transport"
            }),
            None,
        )
        .unwrap();
    }

    fn input(&self) -> Value {
        json!({"allowanceRef":{"schemaVersion":1,"investigationId":"owned-selection",
            "revision":1,"workId":"one-selection"}})
    }

    fn snapshot(&self) -> crate::allowance::AllowanceSnapshot {
        crate::SpendLimiter::open(self.workspace.findings_db_path())
            .unwrap()
            .allowance_snapshot("owned-selection")
            .unwrap()
    }
}

#[derive(Clone)]
struct OfflineRuntime {
    binding: Option<AllowanceBinding>,
    requests: Arc<Mutex<Vec<AgentQueryRequest>>>,
    text: &'static str,
}

impl OfflineRuntime {
    fn new(text: &'static str) -> Self {
        Self {
            binding: None,
            requests: Default::default(),
            text,
        }
    }
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
            .context("Unbudgeted selector query reached")?;
        let reserved = binding.reserve(&request.model)?;
        self.requests.lock().unwrap().push(request);
        let response = AgentQueryResponse {
            text: self.text.into(),
            ..Default::default()
        };
        binding.settle(reserved, response.checked_cost_report()?)?;
        Ok(response)
    }

    fn triage_finding_blocking(&self, _: crate::TriageRequest) -> Result<crate::TriageOutcome> {
        anyhow::bail!("This fixture performs no triage")
    }
}

#[test]
fn unbound_cwe_selection_refuses_before_query() {
    let f = Fixture::new();
    let runtime = OfflineRuntime::new(ANSWER);
    let error = f.dispatch(TOOL, json!({}), Some(&runtime)).unwrap_err();
    assert!(
        format!("{error:#}").contains("approved investigation allowance"),
        "{error:#}"
    );
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn selectors_declare_auxiliary_input_aware_scope_work() {
    let f = Fixture::new();
    let tool = f.registry.resolve_tool(TOOL).unwrap();
    assert_eq!(tool.runtime_requirement, RuntimeRequirement::InputAware);
    assert_eq!(tool.allowance_category, Some(AllowanceCategory::Scope));
    assert_eq!(tool.workspace_requirement, WorkspaceRequirement::Required);
    assert!(!tool.phase_result && tool.hidden);
    assert!(
        !f.registry
            .resolve_tool("pipeline:task-selector")
            .unwrap()
            .phase_result
    );
    assert!(f.registry.tool_wants_runtime(TOOL, &json!({}), &f.config));
    for input in [json!({"cwes":["CWE-20"]}), json!({"cwe":"CWE-20"})] {
        assert!(!f.registry.tool_wants_runtime(TOOL, &input, &f.config));
    }
}

#[test]
fn supplied_classes_need_no_model_or_allowance_and_do_not_query() {
    let mut f = Fixture::new();
    f.config.model = None;
    let runtime = OfflineRuntime::new("No request is permitted");
    for input in [json!({"cwes":["CWE-20"]}), json!({"cwe":"CWE-20"})] {
        let result = f.dispatch(TOOL, input, Some(&runtime)).unwrap();
        assert_eq!(result["status"], "completed");
        assert_eq!(result["data"]["cwes"][0]["id"], "CWE-20");
    }
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert!(!f.root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn approved_selection_uses_one_scope_call_and_keeps_review_capacity() {
    let f = Fixture::new();
    f.approve();
    let runtime = OfflineRuntime::new(ANSWER);
    let result = f.dispatch(TOOL, f.input(), Some(&runtime)).unwrap();
    assert_eq!(result["data"]["cwes"][0]["id"], "CWE-20");
    let output = result["output"].as_str().unwrap();
    assert!(output.contains("CWE-20 · Input validation") && output.contains("Owned source marker"));
    assert!(output.contains("No scan jobs or findings were created"));
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].model, MODEL);
    assert!(requests[0]
        .prompt
        .contains("Owned source marker; never executed."));
    assert!(requests[0].tool_policy.tools.is_empty() && !requests[0].tool_policy.mcps);
    drop(requests);
    let snapshot = f.snapshot();
    assert_eq!(snapshot.committed_calls, 1);
    assert_eq!(snapshot.protected_review_remaining(), 1);
    let error = f.dispatch(TOOL, f.input(), Some(&runtime)).unwrap_err();
    assert!(
        format!("{error:#}").contains("allowance exhausted"),
        "{error:#}"
    );
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert!(!f.root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn malformed_selection_keeps_spending_without_borrowing_review_for_repair() {
    let f = Fixture::new();
    f.approve();
    let runtime = OfflineRuntime::new("not JSON");
    let error = f.dispatch(TOOL, f.input(), Some(&runtime)).unwrap_err();
    assert!(
        format!("{error:#}").contains("structured output"),
        "{error:#}"
    );
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
    assert_eq!(f.snapshot().committed_calls, 1);
    assert_eq!(f.snapshot().protected_review_remaining(), 1);
}

#[test]
fn selection_without_model_has_no_fallback_or_query() {
    let mut f = Fixture::new();
    f.config.model = None;
    let runtime = OfflineRuntime::new(ANSWER);
    let error = f.dispatch(TOOL, json!({}), Some(&runtime)).unwrap_err();
    assert!(format!("{error:#}").contains("explicit model"), "{error:#}");
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn invalid_supplied_classes_fail_without_model_work() {
    let f = Fixture::new();
    let runtime = OfflineRuntime::new(ANSWER);
    let error = f
        .dispatch(TOOL, json!({"cwes":17}), Some(&runtime))
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("string or array"),
        "{error:#}"
    );
    assert!(runtime.requests.lock().unwrap().is_empty());
}
