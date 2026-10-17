use super::*;
use crate::options::{OptionScope, OptionTarget, ToolOptionStore};

#[test]
fn chunked_refuses_supplied_standard_controls_including_aliases_and_default_values() {
    let fixture = Fixture::new();
    for (name, value) in [
        ("includePatterns", json!(["owned.c"])),
        ("exclude_patterns", json!(["other.c"])),
        ("severity", json!(["ERROR"])),
        ("maxFindings", json!(40)),
        ("max_findings", json!(1)),
        ("maxInventoryFiles", json!(80)),
        ("max_inventory_files", json!(1)),
        ("maxBytesPerFile", json!(2048)),
        ("max_bytes_per_file", json!(1)),
        ("maxModelTurns", json!(20)),
        ("max_model_turns", json!(1)),
        ("mode", json!("standard")),
        ("preset", json!("whitebox-static")),
        ("whiteboxStatic", json!(false)),
        ("diff_base", json!("HEAD")),
        ("proofState", json!("source-only")),
        ("staticProofState", json!("source-only")),
        ("proof_states", json!(["source-only"])),
        (
            "AGENTIC_SAST_PROMPT",
            json!("Owned static review instructions."),
        ),
    ] {
        let error = fixture
            .prepare("agentic-sast:scan", json!({name:value}))
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains("requires strategy=standard"),
            "{name}: {text}"
        );
        assert!(text.contains("No model request started."), "{name}: {text}");
    }
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn unenforced_standard_defaults_are_absent_and_chunked_preparation_is_repeatable() {
    let fixture = Fixture::new();
    let first = fixture
        .prepare("agentic-sast:scan", json!({"dryRun":true}))
        .unwrap();
    for name in [
        "mode",
        "maxFindings",
        "maxInventoryFiles",
        "maxBytesPerFile",
        "maxModelTurns",
    ] {
        assert!(
            first.value().get(name).is_none(),
            "Unconsumed default {name}"
        );
    }
    let second = fixture
        .registry
        .prepare_dispatch_input(
            "agentic-sast:scan",
            first.value().clone(),
            &fixture.context(),
            None,
        )
        .unwrap();
    assert_eq!(first.value(), second.value());
    assert_eq!(second.value()["strategy"], "chunked");
}

#[test]
fn stored_standard_settings_require_explicit_removal_or_standard_strategy() {
    let fixture = Fixture::new();
    let mut options = ToolOptionStore::new();
    let target = OptionTarget::Tool("agentic-sast:scan".into());
    options.set_value(
        OptionScope::Global,
        target.clone(),
        "exclude_patterns",
        json!(["other.c"]),
    );
    let prepare = |strategy, store: &ToolOptionStore| {
        fixture.registry.prepare_dispatch_input(
            "agentic-sast:scan",
            json!({"strategy":strategy}),
            &fixture.context(),
            Some(store),
        )
    };
    assert!(prepare("chunked", &options).is_err());
    let standard = prepare("standard", &options).unwrap();
    assert_eq!(standard.value()["excludePatterns"], json!(["other.c"]));
    assert_eq!(standard.value()["maxFindings"], 40);
    assert!(options.unset_value(OptionScope::Global, &target, "exclude_patterns"));
    assert_eq!(
        prepare("chunked", &options).unwrap().value()["strategy"],
        "chunked"
    );
}

#[test]
fn unsupported_inspection_limit_fails_before_runtime_or_allowance_work() {
    let fixture = Fixture::new();
    let error = fixture
        .registry
        .execute_tool(
            "agentic-sast:scan",
            json!({"strategy":"chunked","maxInventoryFiles":1}),
            &fixture.context(),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("option maxInventoryFiles requires strategy=standard"));
    assert!(!fixture.workspace.root().join(".kuzushi/v3/runs").exists());
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn supported_literal_chunk_scope_plans_only_the_selected_source() {
    let fixture = Fixture::new();
    std::fs::write(fixture.workspace.root().join("scope.txt"), "owned.c\n").unwrap();
    let prepared = fixture
        .prepare(
            "agentic-sast:scan",
            json!({"scopeFile":"scope.txt","dryRun":true,"reuseCachedChunks":false}),
        )
        .unwrap();
    let config = full_mode_config_from_input(prepared.value(), &fixture.context()).unwrap();
    let plan = crate::capabilities::full_mode_multi::plan(&config).unwrap();
    let files = plan
        .chunks
        .iter()
        .flat_map(|chunk| &chunk.files)
        .collect::<Vec<_>>();
    assert!(!files.is_empty());
    assert!(files.iter().all(|file| file.path == "owned.c"));
    assert!(!config.reuse_cached_chunks);
}

#[test]
fn descriptor_help_names_strategy_ownership_without_relabeling_shared_settings() {
    let fixture = Fixture::new();
    let tool = fixture.registry.resolve_tool("agentic-sast:scan").unwrap();
    for name in [
        "includePatterns",
        "maxFindings",
        "maxModelTurns",
        "scanScopeRef",
    ] {
        assert!(tool
            .options
            .iter()
            .find(|option| option.name == name)
            .unwrap()
            .description
            .starts_with("Standard strategy only."));
    }
    for name in ["strategy", "scopeFile", "model", "target", "passes"] {
        assert!(!tool
            .options
            .iter()
            .find(|option| option.name == name)
            .unwrap()
            .description
            .starts_with("Standard strategy only."));
    }
}

#[test]
fn chunked_never_binds_an_inapplicable_standard_prompt_file() {
    let fixture = Fixture::new();
    let path =
        crate::options::prompt_override_path(fixture.workspace.root(), "agentic-sast", "scan");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "Owned target-local context. Standard strategy only.").unwrap();
    let chunked = fixture.prepare("agentic-sast:scan", json!({})).unwrap();
    assert!(chunked.value().get("AGENTIC_SAST_PROMPT").is_none());
    let again = fixture
        .prepare("agentic-sast:scan", chunked.value().clone())
        .unwrap();
    assert_eq!(again.value(), chunked.value());
    let standard = fixture
        .registry
        .prepare_dispatch_input("agentic-sast:scan", json!({}), &fixture.context(), None)
        .unwrap();
    assert!(standard
        .value()
        .to_string()
        .contains("Owned target-local context"));
}
