//! Actual shared context dispatch and downstream artifacts; never execute source.
use kuzushi_core::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::path::Path;

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for path in ["root.rs", "alpha/deep/file.py", "zeta/file.rs"] {
        let file = root.path().join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "// Owned context fixture; never executed.\n").unwrap();
    }
    root
}

fn dispatch(root: &Path, tool: &str, input: Value) -> anyhow::Result<Value> {
    let workspace = WorkspaceTarget::new(root)?;
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
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

fn snapshot(root: &Path) -> Value {
    serde_json::from_slice(
        &std::fs::read(kuzushi_core::context::context_snapshot_path(root)).unwrap(),
    )
    .unwrap()
}

#[test]
fn damaged_git_index_preserves_context_and_scope_artifacts() {
    let root = fixture();
    for args in [vec!["init", "--quiet"], vec!["add", "."]] {
        assert!(std::process::Command::new("git")
            .args(args)
            .current_dir(root.path())
            .status()
            .unwrap()
            .success());
    }
    dispatch(root.path(), "context:build", json!({"enrichment":false})).unwrap();
    dispatch(root.path(), "pack:suggest-shards", json!({})).unwrap();
    let paths = [
        kuzushi_core::context::context_snapshot_path(root.path()),
        root.path()
            .join(".kuzushi/v3/reports/suggested-shards.toml"),
    ];
    let prior = paths.each_ref().map(|path| std::fs::read(path).unwrap());
    std::fs::write(
        root.path().join(".git/index"),
        "owned invalid index fixture",
    )
    .unwrap();
    for tool in ["context:build", "pack:suggest-shards"] {
        let error = dispatch(root.path(), tool, json!({})).unwrap_err();
        assert!(format!("{error:#}").contains("filesystem fallback was not used"));
        assert_eq!(
            paths.each_ref().map(|path| std::fs::read(path).unwrap()),
            prior
        );
    }
}

#[test]
fn real_context_reuses_inventory_membership_and_discloses_the_exact_sample() {
    let root = fixture();
    let result = dispatch(
        root.path(),
        "context:build",
        json!({"sampleLimit":2,"enrichment":false}),
    )
    .unwrap();
    let value = snapshot(root.path());
    let inspection = &value["repositoryInventory"]["inspection"];
    assert_eq!(
        value["filesIndexed"],
        inspection["files"].as_array().unwrap().len()
    );
    assert_eq!(value["filesSample"], json!(["root.rs", "zeta/file.rs"]));
    assert_eq!(value["fileIndex"]["enumeration"], "filesystem");
    assert_eq!(value["fileIndex"]["sampleOrder"], "depth_then_path");
    assert_eq!(value["fileIndex"]["truncated"], true);
    assert_eq!(result["data"]["snapshot"]["fileIndex"], value["fileIndex"]);
    let receipt = kuzushi_core::context::context_snapshot_inspection(&value).unwrap();
    assert_eq!((receipt.sampled_files, receipt.enumerated_files), (2, 3));
    assert!(kuzushi_core::context::context_snapshot_freshness(root.path(), &value).is_current());
}

#[test]
fn invalid_limits_and_aliases_are_rejected_before_replacing_prior_bytes() {
    let root = fixture();
    dispatch(root.path(), "context:build", json!({"sampleLimit":1})).unwrap();
    let path = kuzushi_core::context::context_snapshot_path(root.path());
    let before = std::fs::read(&path).unwrap();
    for tool in ["context:build", "context-lite:index"] {
        for key in ["sampleLimit", "limit", "sample_limit"] {
            for value in [
                json!(-1),
                json!(0),
                json!(2001),
                json!(1.5),
                json!("invalid"),
            ] {
                let input = json!({key:value});
                assert!(dispatch(root.path(), tool, input).is_err());
                assert_eq!(std::fs::read(&path).unwrap(), before);
            }
        }
    }
    dispatch(root.path(), "context:build", json!({"limit":2})).unwrap();
    assert_eq!(
        snapshot(root.path())["filesSample"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn repo_and_app_model_scopes_preserve_slice_contracts_without_model_work() {
    let root = fixture();
    dispatch(
        root.path(),
        "context:build",
        json!({"scope":"repo","sampleLimit":2}),
    )
    .unwrap();
    let repo = snapshot(root.path());
    assert!(repo.get("appModel").is_none());
    assert!(repo.get("enrichedContext").is_none());
    dispatch(root.path(), "context:build", json!({"scope":"app-model"})).unwrap();
    let app = snapshot(root.path());
    assert!(app.get("appModel").is_some());
    assert_eq!(repo["repositoryInventory"], app["repositoryInventory"]);
    assert_eq!(repo["fileIndex"], app["fileIndex"]);
    assert!(kuzushi_core::context::context_snapshot_freshness(root.path(), &app).is_current());
}

#[test]
fn pre_cancellation_preserves_the_existing_snapshot_and_never_starts_sampling() {
    let root = fixture();
    dispatch(root.path(), "context:build", json!({})).unwrap();
    let path = kuzushi_core::context::context_snapshot_path(root.path());
    let before = std::fs::read(&path).unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let cancellation = kuzushi_core::scan::ScanCancellation::default();
    cancellation.cancel();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: Some(&cancellation),
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input("context:build", json!({}), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap_err();
    assert!(format!("{error:#}").contains("cancel"), "{error:#}");
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn git_inventory_does_not_silently_expand_to_untracked_source() {
    let root = fixture();
    for args in [
        vec!["init", "--quiet"],
        vec!["add", "root.rs", "zeta/file.rs"],
    ] {
        assert!(std::process::Command::new("git")
            .args(args)
            .current_dir(root.path())
            .status()
            .unwrap()
            .success());
    }
    dispatch(root.path(), "context:build", json!({"sampleLimit":200})).unwrap();
    let value = snapshot(root.path());
    assert_eq!(value["fileIndex"]["enumeration"], "git-index");
    assert_eq!(value["filesSample"], json!(["root.rs", "zeta/file.rs"]));
    let receipt = kuzushi_core::context::context_snapshot_inspection(&value).unwrap();
    assert_eq!(
        receipt.enumeration,
        kuzushi_core::context::ContextEnumeration::GitIndex
    );
    assert_eq!(receipt.enumerated_files, 2);
    assert!(root.path().join("alpha/deep/file.py").exists());
}

#[cfg(unix)]
#[test]
fn ancestor_link_is_disclosed_as_partial_and_cannot_replace_accepted_scopes() {
    let root = fixture();
    for args in [
        vec!["init", "--quiet"],
        vec!["add", "root.rs", "zeta/file.rs"],
    ] {
        assert!(std::process::Command::new("git")
            .args(args)
            .current_dir(root.path())
            .status()
            .unwrap()
            .success());
    }
    dispatch(root.path(), "context:build", json!({"enrichment":false})).unwrap();
    let context_path = kuzushi_core::context::context_snapshot_path(root.path());
    let result = dispatch(
        root.path(),
        "pack:suggest-shards",
        json!({"emitScopes":true}),
    )
    .unwrap();
    let draft_path = Path::new(result["data"]["draftPath"].as_str().unwrap());
    let scopes_path = Path::new(result["data"]["scopesPath"].as_str().unwrap());
    let accepted_scopes = std::fs::read(scopes_path).unwrap();
    let excluded = tempfile::tempdir().unwrap();
    std::fs::write(
        excluded.path().join("file.rs"),
        "// Owned excluded text; never executed.\n",
    )
    .unwrap();
    let excluded_before = std::fs::read(excluded.path().join("file.rs")).unwrap();
    std::fs::rename(root.path().join("zeta"), root.path().join("original-zeta")).unwrap();
    std::os::unix::fs::symlink(excluded.path(), root.path().join("zeta")).unwrap();

    let context = dispatch(root.path(), "context:build", json!({"enrichment":false})).unwrap();
    assert_eq!(context["status"], "partial");
    assert_eq!(context["data"]["partialCoverage"], true);
    assert_eq!(snapshot(root.path())["filesSample"], json!(["root.rs"]));
    let inspection = &context["data"]["snapshot"]["repositoryInventory"]["inspection"];
    assert_eq!(inspection["omitted_paths"][0]["path"], "zeta/file.rs");
    assert!(inspection["omitted_paths"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("symlink"));
    let partial_context = std::fs::read(&context_path).unwrap();
    let proposal = dispatch(root.path(), "pack:suggest-shards", json!({})).unwrap();
    assert_eq!(proposal["status"], "partial");
    assert_eq!(proposal["data"]["inventoryComplete"], false);
    assert_eq!(proposal["data"]["inspection"]["files"], json!(["root.rs"]));
    assert!(std::fs::read_to_string(draft_path)
        .unwrap()
        .contains("# PARTIAL inventory:"));
    let partial_draft = std::fs::read(draft_path).unwrap();
    let error = dispatch(
        root.path(),
        "pack:suggest-shards",
        json!({"emitScopes":true}),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("inventory is incomplete"),
        "{error:#}"
    );
    assert_eq!(std::fs::read(scopes_path).unwrap(), accepted_scopes);
    assert_eq!(std::fs::read(&context_path).unwrap(), partial_context);
    assert_eq!(std::fs::read(draft_path).unwrap(), partial_draft);
    assert_eq!(
        std::fs::read(excluded.path().join("file.rs")).unwrap(),
        excluded_before
    );
}
