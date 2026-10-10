use crate::modules::{ModuleMaturity, ModuleRegistry, RuntimeRequirement, ToolPhase};
use crate::{ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

fn dispatch(tool: &str, input: Value, workspace: Option<&WorkspaceTarget>) -> Value {
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

#[test]
fn operational_descriptors_do_not_claim_mapping_or_need_a_model() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in [
        "config:show",
        "router:show",
        "workspace:status",
        "threat-model:methodologies",
        "engagement:aim",
    ] {
        let descriptor = registry.resolve_tool(name).unwrap();
        assert_eq!(descriptor.phase, ToolPhase::Operate, "{name}");
        assert!(!descriptor.phase_result, "{name}");
        assert_eq!(descriptor.runtime_requirement, RuntimeRequirement::Never);
        assert!(descriptor.headless);
        assert_eq!(crate::modules::phase_result_phase(descriptor), None);
    }
}

#[test]
fn legacy_aim_is_retained_in_exact_dispatch_but_not_default_discovery() {
    let registry = ModuleRegistry::with_v2_builtins();
    assert_eq!(
        registry
            .resolve_tool("engagement:aim")
            .unwrap()
            .discovery_maturity,
        Some(ModuleMaturity::Compatibility)
    );
    assert!(!registry
        .discoverable_tools()
        .any(|tool| tool.name == "engagement:aim"));
}

#[test]
fn status_and_configuration_have_honest_targetless_results() {
    let status = dispatch("workspace:status", json!({}), None);
    assert_eq!(status["status"], "completed");
    assert_eq!(status["data"]["active"], false);
    assert!(status["data"]["root"].is_null());
    let config = dispatch("config:show", json!({}), None);
    assert!(config["data"]["model"].is_null());
    assert!(config["data"]["config"].is_object());
    assert!(config["output"]
        .as_str()
        .unwrap()
        .contains("Model: unconfigured"));
    let router = dispatch("router:show", json!({}), None);
    assert!(router["data"]["configModel"].is_null());
    assert!(router["data"]["roles"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty()));
    assert!(router["output"]
        .as_str()
        .unwrap()
        .contains("Configured routing only"));
}

#[test]
fn active_status_reports_the_explicit_target_and_empty_checkpoint_inventory() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch("workspace:status", json!({}), Some(&workspace));
    assert_eq!(result["data"]["active"], true);
    assert_eq!(
        result["data"]["root"],
        workspace.root().display().to_string()
    );
    assert_eq!(result["data"]["pendingStageCheckpoints"], json!([]));
}

#[test]
fn legacy_harness_budget_is_saved_without_becoming_an_allowance() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let result = dispatch(
        "engagement:aim",
        json!({"focus":"evidence handling", "engines":["context:build"], "budgetUsd":2.5}),
        Some(&workspace),
    );
    assert_eq!(result["data"]["compatibility"]["budgetEnforced"], false);
    assert_eq!(result["data"]["compatibility"]["workApproved"], false);
    assert_eq!(
        result["data"]["compatibility"]["replacementTool"],
        "campaign:study"
    );
    let text = std::fs::read_to_string(workspace.root().join("engagement/harness.toml")).unwrap();
    let saved: crate::engagement::EngagementHarness = toml::from_str(&text).unwrap();
    assert_eq!(saved.budget_usd, Some(2.5));
    assert!(!workspace.root().join(".kuzushi/v3/campaigns").exists());
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("Recorded budget is not enforced"));
}

#[test]
fn undeclared_operational_options_fail_before_a_legacy_file_is_written() {
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
    let registry = ModuleRegistry::with_v2_builtins();
    for name in [
        "config:show",
        "router:show",
        "workspace:status",
        "threat-model:methodologies",
        "engagement:aim",
    ] {
        assert!(registry
            .prepare_dispatch_input(name, json!({"unapprovedWork":true}), &ctx, None)
            .is_err());
    }
    assert!(!workspace.root().join("engagement/harness.toml").exists());
}

#[test]
fn methodology_listing_produces_a_readable_catalog_without_workspace_artifacts() {
    let result = dispatch("threat-model:methodologies", json!({}), None);
    assert_eq!(result["status"], "completed");
    assert!(result["output"]
        .as_str()
        .is_some_and(|output| !output.trim().is_empty()));
    assert!(!result["data"].is_null());
}
