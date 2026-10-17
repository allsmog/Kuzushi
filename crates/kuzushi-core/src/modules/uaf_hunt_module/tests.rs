use super::*;
use crate::findings::FindingStore;
use crate::{ModuleRegistry, V2Config, WorkspaceTarget};

#[test]
fn structured_pairs_pass_shared_preparation_without_admitting_unknown_keys() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let context = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    for field in ["allocFreePairs", "extraAllocFreePairs"] {
        let input = json!({field: [{"alloc":"owned_alloc", "free":"owned_free"}]});
        registry
            .prepare_dispatch_input("uaf-hunt:hunt", input, &context, None)
            .unwrap();
    }
    let error = registry
        .prepare_dispatch_input(
            "uaf-hunt:hunt",
            json!({"unknownOwnedOption":true}),
            &context,
            None,
        )
        .err()
        .unwrap();
    assert!(error.to_string().contains("unknown option"));
}

#[test]
fn experimental_uaf_limits_are_declared_and_prepared_canonically() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let tool = registry.resolve_tool("uaf-hunt:hunt").unwrap();
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
    assert!(!tool.phase_result);
    for (key, default, maximum) in [("maxAgentSteps", 120, 400), ("clangTimeoutSecs", 60, 300)] {
        let option = tool.options.iter().find(|o| o.name == key).unwrap();
        assert_eq!(option.default, Some(json!(default)));
        assert_eq!(option.minimum, Some(1));
        assert_eq!(option.maximum, Some(maximum));
        for value in [0, maximum + 1] {
            assert!(registry
                .prepare_dispatch_input("uaf-hunt:hunt", json!({key:value}), &ctx, None)
                .is_err());
        }
    }
    registry
        .prepare_dispatch_input(
            "uaf-hunt:hunt",
            json!({"max_agent_steps":1,"clang_timeout_secs":1}),
            &ctx,
            None,
        )
        .unwrap();
}

#[test]
fn external_compiler_input_is_explicit_without_expanding_workspace_read_paths() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let path = outside.path().join("chosen.json");
    std::fs::write(&path, "[]").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    assert!(registry
        .prepare_dispatch_input(
            "uaf-hunt:hunt",
            json!({"compileCommandsPath":path}),
            &ctx,
            None
        )
        .is_err());
    registry
        .prepare_dispatch_input(
            "uaf-hunt:hunt",
            json!({"external_compile_commands_path":path}),
            &ctx,
            None,
        )
        .unwrap();
    let descriptor = registry.resolve_tool("uaf-hunt:hunt").unwrap();
    let option = descriptor
        .options
        .iter()
        .find(|o| o.name == "externalCompileCommandsPath")
        .unwrap();
    assert_eq!(
        option.path_semantics,
        Some(kuzushi_descriptor::PathSemantics::ExternalRead)
    );
    assert!(option.path_semantics.unwrap().forbids_workspace_storage());
    assert!(
        crate::capabilities::uaf_hunt::adapters::parse_uaf_hunt_input(
            &json!({"compileCommandsPath":"chosen.json","externalCompileCommandsPath":path}),
            root.path()
        )
        .is_err()
    );
}
