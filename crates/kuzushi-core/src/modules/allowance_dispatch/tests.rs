use super::*;
use crate::{allowance::AllowanceLimits, V2Config, WorkspaceTarget};

const MODEL: &str = "openai-codex:gpt-5.5";

pub(super) fn context<'a>(workspace: &'a WorkspaceTarget, config: &'a V2Config) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config, workspace: Some(workspace), findings_store: None, trace: None,
        cancellation: None, authorization: Default::default(),
    }
}

pub(super) fn approval() -> Value {
    json!({"investigationId":"study", "expectedRevision":0, "model":MODEL,
        "maxProviderCalls":3,"protectedReviewCalls":1,"reason":"Offline approval test"})
}

fn allowance_ref() -> Value {
    json!({"schemaVersion":1,"investigationId":"study","revision":1,"workId":"pass-1"})
}

fn approve(registry: &ModuleRegistry, ctx: &ToolExecutionContext<'_>, input: Value) -> Result<Value> {
    let prepared = registry.prepare_dispatch_input("campaign:approve-allowance", input, ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, ctx, None)
}

#[test]
fn reading_an_unapproved_allowance_does_not_create_a_ledger() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let error = registry.execute_tool("campaign:allowance", json!({"investigationId":"missing"}), &ctx).unwrap_err();
    assert!(error.to_string().contains("no approved allowance"));
    assert!(!workspace.findings_db_path().exists());
}

#[test]
fn allowance_approval_requires_authorization_and_status_survives_restart() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry.prepare_dispatch_input("campaign:approve-allowance", approval(), &ctx, None).unwrap();
    let error = registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None).unwrap_err();
    assert!(error.to_string().contains("explicit operator authorization"));
    assert!(open_ledger(&ctx).unwrap().allowance_snapshot("study").is_err());
    let result = approve(&registry, &ctx, approval()).unwrap();
    assert_eq!(result["data"]["allowance"]["revision"], 1);
    assert!(result["summary"].as_str().unwrap().contains("no jobs started"));
    assert!(!registry.resolve_tool("campaign:approve-allowance").unwrap().phase_result);
    let status = registry.execute_tool("campaign:allowance", json!({"investigationId":"study"}), &ctx).unwrap();
    assert_eq!(status["data"]["allowance"]["committedCalls"], 0);
    assert_eq!(status["data"]["dollarCeilingEnforced"], false);
    assert!(!crate::capabilities::campaign::campaigns_dir(root.path()).exists());
}

#[test]
fn approval_rejects_stale_revision_unknown_keys_and_invalid_limits() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    approve(&registry, &ctx, approval()).unwrap();
    assert!(approve(&registry, &ctx, approval()).unwrap_err().to_string().contains("revision changed"));
    for (key, value) in [("unknown", json!(true)), ("maxProviderCalls", json!(0)), ("protectedReviewCalls", json!(4))] {
        let mut input = approval();
        input["expectedRevision"] = json!(1);
        input[key] = value;
        assert!(approve(&registry, &ctx, input).is_err(), "{key}");
    }
    let snapshot = open_ledger(&ctx).unwrap().allowance_snapshot("study").unwrap();
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.limits, AllowanceLimits { max_provider_calls: 3, protected_review_calls: 1 });
}

#[test]
fn allowance_reference_is_validated_before_execution_and_cannot_select_work_category() {
    let registry = ModuleRegistry::with_v2_builtins();
    for value in [Value::Null, json!({}), json!({"schemaVersion":2,"investigationId":"study","revision":1,"workId":"pass-1"})] {
        assert!(registry.prepare_tool_input("context:build", json!({"allowanceRef":value}), None).is_err());
    }
    let mut value = allowance_ref();
    value["work"] = json!("review");
    assert!(registry.prepare_tool_input("context:build", json!({"allowanceRef":value}), None).is_err());
    assert!(registry.prepare_tool_input("context:build", json!({"allowanceRef":allowance_ref()}), None).is_ok());
    assert_eq!(phase_work(ToolPhase::Scan), Some(InvestigationWork::Discovery));
    assert_eq!(phase_work(ToolPhase::Review), Some(InvestigationWork::Review));
}

#[test]
fn deterministic_dispatch_validates_allowance_without_needing_model_or_spending() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let input = json!({"allowanceRef":allowance_ref()});
    assert!(registry.execute_tool("context:build", input.clone(), &ctx).is_err());
    approve(&registry, &ctx, approval()).unwrap();
    let result = registry.execute_tool("context:build", input, &ctx).unwrap();
    assert!(result.get("data").is_some());
    assert_eq!(open_ledger(&ctx).unwrap().allowance_snapshot("study").unwrap().committed_calls, 0);
    assert!(workspace.root().join(".kuzushi/context-snapshot.json").exists());
}

#[test]
fn descriptor_governance_is_removed_only_from_executor_input() {
    let input = json!({"allowanceRef":allowance_ref(),"model":MODEL,"enrichment":true});
    let stripped = executor_input(&input);
    assert!(input.get("allowanceRef").is_some());
    assert_eq!(stripped.as_ref(), &json!({"model":MODEL,"enrichment":true}));
    assert!(matches!(executor_input(stripped.as_ref()), std::borrow::Cow::Borrowed(_)));
}

struct UnsupportedRuntime;
#[async_trait::async_trait]
impl AgentRuntime for UnsupportedRuntime {
    fn preflight_model_blocking(&self, _model: &str) -> Result<()> {
        panic!("unsupported runtime must be refused before model preflight")
    }
    fn triage_finding_blocking(&self, _request: crate::TriageRequest) -> Result<crate::TriageOutcome> {
        unreachable!()
    }
}

#[test]
fn unsupported_runtime_and_model_drift_fail_before_preflight_or_executor() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let mut config = V2Config::default();
    config.model = Some(MODEL.into());
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    approve(&registry, &ctx, approval()).unwrap();
    for model in [MODEL, "openai-codex:changed"] {
        let input = json!({"model":model,"enrichment":true,"allowanceRef":allowance_ref()});
        let error = registry.execute_tool_with_runtime("context:build", input, &ctx, Some(&UnsupportedRuntime)).unwrap_err();
        assert_eq!(crate::runtime::runtime_failure_metadata(&error).unwrap().error_class, crate::RuntimeFailureClass::AllowanceRefused);
    }
    assert_eq!(open_ledger(&ctx).unwrap().allowance_snapshot("study").unwrap().committed_calls, 0);
}
