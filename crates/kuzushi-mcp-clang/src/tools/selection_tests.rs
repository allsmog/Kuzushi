use super::*;
use kuzushi_mcp_common::tool::ToolRegistry;
use kuzushi_mcp_common::ReadRootCapability;
use serde_json::json;

fn command(repo: &std::path::Path, selected: bool) -> serde_json::Value {
    json!([{"directory":repo,"file":"owned.c","arguments":["clang",format!("-DOWNED_SELECTED={}",u8::from(selected)),"-c","owned.c"]}])
}

#[tokio::test]
async fn explicit_database_metadata_uses_the_declared_schema_and_read_roots() {
    let root = tempfile::tempdir().unwrap();
    let chosen = root.path().join("chosen.json");
    std::fs::write(
        &chosen,
        serde_json::to_vec(&command(root.path(), true)).unwrap(),
    )
    .unwrap();
    let registry = build_registry_with_capability(
        ReadRootCapability::new([root.path().to_path_buf()]).unwrap(),
    );
    let result = registry
        .call(
            "clang.compile_commands",
            json!({"repoPath":root.path(),"compileCommandsPath":"chosen.json"}),
        )
        .await
        .unwrap();
    assert_eq!(result["entries"], 1);
    assert_eq!(result["generator"], "pre_existing");
    assert_eq!(
        result["configuration"]["sourceSha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(registry
        .call(
            "clang.compile_commands",
            json!({"repoPath":root.path(),"compileCommandsPath":"../ungranted.json"})
        )
        .await
        .is_err());
    assert_compiler_option_schema(&registry);
}

fn assert_compiler_option_schema(registry: &ToolRegistry) {
    for tool in registry
        .descriptors()
        .iter()
        .filter(|tool| tool.name != "clang.health")
    {
        assert_eq!(
            tool.input_schema["properties"]["compileCommandsPath"]["type"],
            "string"
        );
    }
}

#[tokio::test]
#[ignore = "requires installed clangd and a verified read-only OS sandbox"]
async fn selected_database_drives_real_clangd_and_changes_invalidate_the_cached_client() {
    assert!(kuzushi_mcp_common::read_only_sandbox::sandbox_available().await);
    assert!(kuzushi_mcp_common::doctor::which("clangd").is_some());
    let root = tempfile::tempdir().unwrap();
    let code = seed_compiler_selection(root.path());
    let custom = root.path().join("chosen.json");
    let registry = build_registry_with_capability(
        ReadRootCapability::new([root.path().to_path_buf()]).unwrap(),
    );
    let args = json!({"repoPath":root.path(),"compileCommandsPath":"chosen.json","file":"owned.c","line":6,"column":30});
    assert_legacy_lookup_has_no_selected_definition(&registry, args.clone()).await;
    for selected in [true, false, true] {
        std::fs::write(
            &custom,
            serde_json::to_vec(&command(root.path(), selected)).unwrap(),
        )
        .unwrap();
        let result = registry
            .call("clang.definition", args.clone())
            .await
            .unwrap();
        let locations = result["locations"].as_array().unwrap();
        assert_eq!(!locations.is_empty(), selected, "{result}");
        if selected {
            assert_eq!(locations[0]["line"], 2);
        }
    }
    assert_eq!(
        std::fs::read_to_string(root.path().join("owned.c")).unwrap(),
        code
    );
    assert!(!root.path().join("owned.o").exists());
}

async fn assert_legacy_lookup_has_no_selected_definition(
    registry: &ToolRegistry,
    mut args: serde_json::Value,
) {
    args.as_object_mut().unwrap().remove("compileCommandsPath");
    assert!(
        registry.call("clang.definition", args).await.unwrap()["locations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

fn seed_compiler_selection(root: &std::path::Path) -> &'static str {
    let code = "#if OWNED_SELECTED\nint owned_selected;\n#else\nint unselected;\n#endif\nint inspected(void) { return owned_selected; }\n";
    std::fs::write(root.join("owned.c"), code).unwrap();
    std::fs::write(
        root.join(".clangd"),
        "CompileFlags:\n  Remove: [-DOWNED_SELECTED=*]\n  Add: [-DOWNED_SELECTED=0]\n",
    )
    .unwrap();
    std::fs::write(
        root.join("compile_commands.json"),
        serde_json::to_vec(&command(root, false)).unwrap(),
    )
    .unwrap();
    code
}
