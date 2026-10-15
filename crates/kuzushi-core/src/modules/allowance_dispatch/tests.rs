use super::*;
use crate::{allowance::AllowanceLimits, V2Config, WorkspaceTarget};

const MODEL: &str = "openai-codex:gpt-5.5";

#[test]
fn finite_planning_and_approval_publish_no_map_phase_result() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in [
        "campaign:study",
        "campaign:context-study",
        "campaign:approve-allowance",
    ] {
        let tool = registry.resolve_tool(name).unwrap();
        assert!(!tool.phase_result, "{name}");
        assert_eq!(tool.runtime_requirement, RuntimeRequirement::Never);
    }
    assert_eq!(
        registry.resolve_tool("campaign:allowance").unwrap().phase,
        ToolPhase::Operate
    );
}

#[test]
fn learning_category_overrides_review_phase_without_changing_legacy_descriptors() {
    let legacy = super::super::findings_relationships::relationship_tools().remove(0);
    assert_eq!(descriptor_work(&legacy), Some(InvestigationWork::Review));
    assert!(serde_json::to_value(&legacy)
        .unwrap()
        .get("allowance_category")
        .is_none());
    let learning = legacy.with_allowance_category(AllowanceCategory::Learning);
    assert_eq!(
        descriptor_work(&learning),
        Some(InvestigationWork::Learning)
    );
    let restored: ToolDescriptor =
        serde_json::from_value(serde_json::to_value(&learning).unwrap()).unwrap();
    assert_eq!(
        restored.allowance_category,
        Some(AllowanceCategory::Learning)
    );
}

#[test]
fn external_actions_opt_into_allowance_without_weakening_authorization() {
    let registry = ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("ndiff:extract-fix-pattern").unwrap();
    assert_eq!(tool.effect, ToolEffect::ExternalAction);
    assert!(tool
        .options
        .iter()
        .any(|option| option.name == "allowanceRef"));
    assert_eq!(descriptor_work(&tool), Some(InvestigationWork::Learning));
    let mut legacy = tool.clone();
    legacy.allowance_category = None;
    assert!(!supports_allowance(&legacy));
    assert!(supports_allowance(&tool));
    assert_eq!(tool.approval, legacy.approval);
}

#[test]
fn categorized_external_actions_cannot_inherit_parent_review_capacity() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    approve(&registry, &ctx, approval()).unwrap();
    let mut work = AllowanceWork {
        investigation_id: "study".into(),
        revision: 1,
        run_id: "owned-parent".into(),
        work_id: "parent".into(),
        model: MODEL.into(),
        work: InvestigationWork::Review,
    };
    let binding = AllowanceBinding::new(open_ledger(&ctx).unwrap(), work.clone()).unwrap();
    let tool = registry.resolve_tool("ndiff:extract-fix-pattern").unwrap();
    assert!(require_declared_effect_category(&tool, &binding).is_err());
    work.work = InvestigationWork::Learning;
    let binding = AllowanceBinding::new(open_ledger(&ctx).unwrap(), work).unwrap();
    require_declared_effect_category(&tool, &binding).unwrap();
}

pub(super) fn context<'a>(
    workspace: &'a WorkspaceTarget,
    config: &'a V2Config,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

pub(super) fn approval() -> Value {
    json!({"investigationId":"study", "expectedRevision":0, "model":MODEL,
        "maxProviderCalls":3,"protectedReviewCalls":1,"reason":"Offline approval test"})
}

fn allowance_ref() -> Value {
    json!({"schemaVersion":1,"investigationId":"study","revision":1,"workId":"pass-1"})
}

fn approve(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    input: Value,
) -> Result<Value> {
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", input, ctx, None)?
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
    let error = registry
        .execute_tool(
            "campaign:allowance",
            json!({"investigationId":"missing"}),
            &ctx,
        )
        .unwrap_err();
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
    let prepared = registry
        .prepare_dispatch_input("campaign:approve-allowance", approval(), &ctx, None)
        .unwrap();
    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("explicit operator authorization"));
    assert!(open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .is_err());
    let result = approve(&registry, &ctx, approval()).unwrap();
    assert_eq!(result["data"]["allowance"]["revision"], 1);
    assert!(result["summary"]
        .as_str()
        .unwrap()
        .contains("no jobs started"));
    assert!(
        !registry
            .resolve_tool("campaign:approve-allowance")
            .unwrap()
            .phase_result
    );
    let status = registry
        .execute_tool(
            "campaign:allowance",
            json!({"investigationId":"study"}),
            &ctx,
        )
        .unwrap();
    assert_eq!(status["data"]["allowance"]["committedCalls"], 0);
    assert!(status["summary"]
        .as_str()
        .unwrap()
        .contains("Calls available for context, scopes, scans and lessons: 2"));
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
    assert!(approve(&registry, &ctx, approval())
        .unwrap_err()
        .to_string()
        .contains("revision changed"));
    for (key, value) in [
        ("unknown", json!(true)),
        ("maxProviderCalls", json!(-1)),
        ("protectedReviewCalls", json!(4)),
    ] {
        let mut input = approval();
        input["expectedRevision"] = json!(1);
        input[key] = value;
        assert!(approve(&registry, &ctx, input).is_err(), "{key}");
    }
    let snapshot = open_ledger(&ctx)
        .unwrap()
        .allowance_snapshot("study")
        .unwrap();
    assert_eq!(snapshot.revision, 1);
    assert_eq!(
        snapshot.limits,
        AllowanceLimits {
            max_provider_calls: 3,
            protected_review_calls: 1
        }
    );
}

#[test]
fn allowance_reference_is_validated_before_execution_and_cannot_select_work_category() {
    let registry = ModuleRegistry::with_v2_builtins();
    for value in [
        Value::Null,
        json!({}),
        json!({"schemaVersion":2,"investigationId":"study","revision":1,"workId":"pass-1"}),
    ] {
        assert!(registry
            .prepare_tool_input("context:build", json!({"allowanceRef":value}), None)
            .is_err());
    }
    let mut value = allowance_ref();
    value["work"] = json!("review");
    assert!(registry
        .prepare_tool_input("context:build", json!({"allowanceRef":value}), None)
        .is_err());
    assert!(registry
        .prepare_tool_input(
            "context:build",
            json!({"allowanceRef":allowance_ref()}),
            None
        )
        .is_ok());
    assert_eq!(
        phase_work(ToolPhase::Scan),
        Some(InvestigationWork::Discovery)
    );
    assert_eq!(
        phase_work(ToolPhase::Review),
        Some(InvestigationWork::Review)
    );
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
    assert!(registry
        .execute_tool("context:build", input.clone(), &ctx)
        .is_err());
    approve(&registry, &ctx, approval()).unwrap();
    let result = registry.execute_tool("context:build", input, &ctx).unwrap();
    assert_eq!(result["allowanceRef"], allowance_ref());
    assert!(result.get("data").is_some());
    assert_eq!(
        open_ledger(&ctx)
            .unwrap()
            .allowance_snapshot("study")
            .unwrap()
            .committed_calls,
        0
    );
    assert!(workspace
        .root()
        .join(".kuzushi/context-snapshot.json")
        .exists());
}

#[test]
fn descriptor_governance_is_removed_only_from_executor_input() {
    let input = json!({"allowanceRef":allowance_ref(),"model":MODEL,"enrichment":true});
    let stripped = executor_input(&input);
    assert!(input.get("allowanceRef").is_some());
    assert_eq!(stripped.as_ref(), &json!({"model":MODEL,"enrichment":true}));
    assert!(matches!(
        executor_input(stripped.as_ref()),
        std::borrow::Cow::Borrowed(_)
    ));
}

#[test]
fn engines_cannot_forge_result_accounting_and_invalid_references_are_rejected() {
    let forged =
        json!({"schemaVersion":1,"investigationId":"foreign","revision":4,"workId":"fake"});
    let mut result = json!({"ok":true,"data":{"kept":true},"allowanceRef":forged});
    attach_result_reference(&json!({}), &mut result).unwrap();
    assert!(result.get("allowanceRef").is_none());
    result["allowanceRef"] = forged;
    attach_result_reference(&json!({"allowanceRef":allowance_ref()}), &mut result).unwrap();
    assert_eq!(result["allowanceRef"], allowance_ref());
    assert_eq!(result["data"], json!({"kept":true}));
    assert!(attach_result_reference(&json!({"allowanceRef":null}), &mut result).is_err());
}

struct UnsupportedRuntime;
#[async_trait::async_trait]
impl AgentRuntime for UnsupportedRuntime {
    fn preflight_model_blocking(&self, _model: &str) -> Result<()> {
        panic!("unsupported runtime must be refused before model preflight")
    }
    fn triage_finding_blocking(
        &self,
        _request: crate::TriageRequest,
    ) -> Result<crate::TriageOutcome> {
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
        let error = registry
            .execute_tool_with_runtime("context:build", input, &ctx, Some(&UnsupportedRuntime))
            .unwrap_err();
        assert_eq!(
            crate::runtime::runtime_failure_metadata(&error)
                .unwrap()
                .error_class,
            crate::RuntimeFailureClass::AllowanceRefused
        );
    }
    assert_eq!(
        open_ledger(&ctx)
            .unwrap()
            .allowance_snapshot("study")
            .unwrap()
            .committed_calls,
        0
    );
}

#[test]
fn exhausted_allowance_refuses_runtime_work_before_preflight_or_executor() {
    use crate::allowance::{AllowanceCall, InvestigationWork};
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("main.rs"), "// Owned context fixture.\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some(MODEL.into()),
        ..Default::default()
    };
    let ctx = context(&workspace, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    approve(&registry, &ctx, approval()).unwrap();
    let ledger = open_ledger(&ctx).unwrap();
    for id in ["earlier-one", "earlier-two"] {
        ledger
            .reserve_provider_call(&AllowanceCall {
                investigation_id: "study".into(),
                expected_revision: 1,
                request_id: id.into(),
                run_id: "earlier-context".into(),
                work_id: "pass-1".into(),
                model: MODEL.into(),
                work: InvestigationWork::Context,
            })
            .unwrap();
    }
    let input = json!({"model":MODEL,"enrichment":true,"allowanceRef":allowance_ref()});
    let error = registry
        .execute_tool_with_runtime("context:build", input, &ctx, Some(&UnsupportedRuntime))
        .unwrap_err();
    assert!(format!("{error:#}").contains("allowance exhausted"));
    assert!(!workspace
        .root()
        .join(".kuzushi/context-snapshot.json")
        .exists());
    let after = ledger.allowance_snapshot("study").unwrap();
    assert_eq!(
        (
            after.committed_calls,
            after.unresolved_calls,
            after.protected_review_remaining()
        ),
        (2, 2, 1)
    );
}
