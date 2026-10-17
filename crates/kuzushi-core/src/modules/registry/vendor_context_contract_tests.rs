use crate::modules::{
    phase_result_phase, AllowanceCategory, ModuleMaturity, ModuleRegistry, ToolPhase,
};
use crate::options::{OptionScope, OptionTarget, ToolOptionStore};
use crate::{ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::json;

#[test]
fn auxiliary_vendor_actions_never_own_repository_phase_results() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    for name in ["scope", "attach", "prompts", "assess"] {
        let tool = registry
            .resolve_tool(&format!("vendor-assessment:{name}"))
            .unwrap();
        assert!(!tool.phase_result);
        assert_eq!(phase_result_phase(tool), None);
    }
    let tool = registry.resolve_tool("vendor-assessment:assess").unwrap();
    assert_eq!(tool.phase, ToolPhase::Review);
    assert_eq!(tool.allowance_category, Some(AllowanceCategory::Review));
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
}

#[test]
fn shared_preparation_preserves_profile_and_exposes_clear_only_on_scope() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    registry
        .execute_tool(
            "vendor-assessment:scope",
            json!({"profile":"operator-profile"}),
            &ctx,
        )
        .unwrap();
    let path = root.path().join(".kuzushi/vendor-assessment/scope.json");
    let before = std::fs::read(&path).unwrap();
    let value = registry
        .execute_tool("vendor-assessment:scope", json!({}), &ctx)
        .unwrap();
    assert_eq!(value["data"]["scope"]["profile"], "operator-profile");
    assert!(value["output"]
        .as_str()
        .unwrap()
        .contains("Profile: operator-profile"));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_prompt_cannot_clear(&registry, &ctx);
    let clear = registry
        .execute_tool("vendor-assessment:scope", json!({"clear":true}), &ctx)
        .unwrap();
    assert_eq!(clear["data"]["cleared"], true);
}

fn assert_prompt_cannot_clear(registry: &ModuleRegistry, ctx: &ToolExecutionContext<'_>) {
    assert!(registry
        .prepare_dispatch_input(
            "vendor-assessment:prompts",
            json!({"clear":true}),
            ctx,
            None
        )
        .is_err());
}

#[test]
fn target_local_options_cannot_steer_vendor_evidence_sources() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    for key in ["source", "path", "url", "target", "input"] {
        let mut store = ToolOptionStore::new();
        store.set_value(
            OptionScope::Workspace,
            OptionTarget::Tool("vendor-assessment:attach".into()),
            key,
            json!("/tmp/not-opened-by-this-test"),
        );
        let error = registry
            .prepare_dispatch_input("vendor-assessment:attach", json!({}), &ctx, Some(&store))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("workspace"),
            "{key}: {error:#}"
        );
    }
}
