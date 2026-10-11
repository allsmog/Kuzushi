//! Shared prepared dispatch over owned inert pack and source fixtures.
use kuzushi_core::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::path::Path;

fn fixture() -> (tempfile::TempDir, tempfile::TempDir) {
    let pack = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    std::fs::write(pack.path().join("pack.toml"), "[pack]\nname='owned'\n[products.example]\ntarget_hint='owned'\nshards='shards.toml'\nthreat_model='model.json'\n").unwrap();
    std::fs::write(
        pack.path().join("shards.toml"),
        "[shards.whole]\npaths=['.']\n",
    )
    .unwrap();
    std::fs::write(
        pack.path().join("model.json"),
        r#"{"threats":[{"id":"owned","title":"Labeled schema fixture","severity":"info"}]}"#,
    )
    .unwrap();
    std::fs::write(
        target.path().join("source.rs"),
        "// owned, never executed\n",
    )
    .unwrap();
    (pack, target)
}

fn dispatch(root: Option<&Path>, tool: &str, input: Value) -> anyhow::Result<Value> {
    let workspace = root.map(WorkspaceTarget::new).transpose()?;
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: workspace.as_ref(),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

#[test]
fn pack_lint_shared_options_bound_work_and_missing_target_is_partial() {
    let (pack, target) = fixture();
    let input = json!({"packDir":pack.path()});
    let complete = dispatch(Some(target.path()), "pack:lint", input.clone()).unwrap();
    assert_eq!(complete["status"], "completed", "{complete}");
    assert_eq!(complete["data"]["coverage"]["complete"], true);
    let targetless = dispatch(None, "pack:lint", input).unwrap();
    assert_eq!(targetless["status"], "partial");
    assert_eq!(targetless["data"]["coverage"]["complete"], false);
    let limited = dispatch(
        Some(target.path()),
        "pack:lint",
        json!({"packDir":pack.path(),"maxWalkEntries":1}),
    )
    .unwrap();
    assert_eq!(limited["status"], "partial");
    assert_eq!(limited["data"]["coverage"]["entriesExamined"], 1);
}

#[test]
fn invalid_pack_limits_and_unknown_options_refuse_execution() {
    let (pack, target) = fixture();
    for input in [
        json!({"packDir":pack.path(),"maxReadBytes":0}),
        json!({"packDir":pack.path(),"maxWalkEntries":100001}),
        json!({"packDir":pack.path(),"unrecognized":true}),
    ] {
        assert!(dispatch(Some(target.path()), "pack:lint", input).is_err());
    }
}

#[test]
fn malformed_or_oversized_documents_fail_with_honest_coverage() {
    let (pack, target) = fixture();
    let oversized = dispatch(
        Some(target.path()),
        "pack:lint",
        json!({"packDir":pack.path(),"maxBytesPerFile":16,"maxReadBytes":16}),
    )
    .unwrap();
    assert_eq!(oversized["status"], "failed");
    assert_eq!(oversized["data"]["coverage"]["complete"], false);
    assert_eq!(oversized["data"]["coverage"]["reservedReadBytes"], 16);
    std::fs::write(pack.path().join("model.json"), "invalid owned json").unwrap();
    let malformed = dispatch(
        Some(target.path()),
        "pack:lint",
        json!({"packDir":pack.path()}),
    )
    .unwrap();
    assert_eq!(malformed["status"], "failed");
    assert!(malformed["data"]["errors"].as_u64().unwrap() > 0);
}

#[cfg(unix)]
#[test]
fn pack_lint_excludes_symlink_cycles_and_outside_membership() {
    let (pack, target) = fixture();
    std::os::unix::fs::symlink(target.path(), target.path().join("cycle")).unwrap();
    let partial = dispatch(
        Some(target.path()),
        "pack:lint",
        json!({"packDir":pack.path()}),
    )
    .unwrap();
    assert_eq!(partial["status"], "partial", "{partial}");
    std::fs::write(
        pack.path().join("shards.toml"),
        format!(
            "[shards.outside]\npaths=[{:?}]\n",
            pack.path().to_str().unwrap()
        ),
    )
    .unwrap();
    let outside = dispatch(
        Some(target.path()),
        "pack:lint",
        json!({"packDir":pack.path()}),
    )
    .unwrap();
    assert_eq!(outside["data"]["coverage"]["complete"], false);
    assert!(outside["data"]["coverage"]["reasonSamples"]
        .to_string()
        .contains("escapes workspace"));
}

#[test]
fn legacy_suggester_dispatch_remains_available_without_accepting_modern_scopes() {
    let (_pack, target) = fixture();
    std::fs::write(target.path().join("README.md"), "Owned root membership\n").unwrap();
    let source = std::fs::read(target.path().join("source.rs")).unwrap();
    let result = dispatch(Some(target.path()), "pack:suggest-shards", json!({})).unwrap();
    assert_eq!(result["status"], "completed", "{result}");
    assert_eq!(result["data"]["inventoryComplete"], true);
    let draft = Path::new(result["data"]["draftPath"].as_str().unwrap());
    assert!(draft.exists());
    assert!(!target.path().join(".kuzushi/shards.toml").exists());
    assert!(!target
        .path()
        .join(".kuzushi/v3/scan-scopes/revisions")
        .exists());
    assert_eq!(
        std::fs::read(target.path().join("source.rs")).unwrap(),
        source
    );
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    assert!(
        !registry
            .resolve_tool("pack:suggest-shards")
            .unwrap()
            .phase_result
    );
    assert!(!registry.resolve_tool("pack:lint").unwrap().phase_result);
    assert!(registry
        .resolve_tool("pack:suggest-shards")
        .unwrap()
        .discovery_maturity
        .is_some());
}

#[cfg(unix)]
#[test]
fn dangling_pack_documents_are_unavailable_and_retain_read_reservations() {
    let (pack, target) = fixture();
    std::fs::remove_file(pack.path().join("model.json")).unwrap();
    std::os::unix::fs::symlink(pack.path().join("absent"), pack.path().join("model.json")).unwrap();
    let result = dispatch(
        Some(target.path()),
        "pack:lint",
        json!({"packDir":pack.path()}),
    )
    .unwrap();
    assert_eq!(result["status"], "failed");
    assert_eq!(result["data"]["coverage"]["complete"], false);
    assert!(
        result["data"]["coverage"]["reservedReadBytes"]
            .as_u64()
            .unwrap()
            >= 8 * 1024 * 1024
    );
}
