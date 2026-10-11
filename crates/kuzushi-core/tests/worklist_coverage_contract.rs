use kuzushi_core::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::path::Path;

fn dispatch(root: &Path, name: &str, input: Value) -> anyhow::Result<Value> {
    dispatch_with_store(root, name, input, None)
}

fn dispatch_with_store(
    root: &Path,
    name: &str,
    input: Value,
    store: Option<&kuzushi_core::findings::FindingStore>,
) -> anyhow::Result<Value> {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let workspace = WorkspaceTarget::new(root)?;
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: store,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let input = registry
        .prepare_dispatch_input(name, input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(input, &ctx, None)
}

fn write_surface_density(root: &Path, path: &str) {
    let file = kuzushi_core::context::context_snapshot_path(root);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(
        file,
        json!({"attackSurfaceMap": {"rootName":"owned synthetic metadata",
        "surfaces":[{"id":"owned-synthetic","kind":"cli_entrypoint","path":path,
            "line":1,"language":"rust","title":"Synthetic metadata","evidence":"Synthetic metadata",
            "risk":{"rank":1,"score":42,"tier":"medium","reasons":[]},"metadata":null}],
        "summary":{"total":1,"byKind":{"cli_entrypoint":1},"byFile":{path:1}}}})
        .to_string(),
    )
    .unwrap();
}

#[test]
fn ranking_is_auxiliary_and_cannot_complete_map() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let descriptor = registry.resolve_tool("worklist:rank").unwrap();
    assert_eq!(descriptor.phase, kuzushi_core::modules::ToolPhase::Map);
    assert!(!descriptor.phase_result);
}

#[test]
fn explicit_target_is_used_and_reported_without_creating_a_child_store() {
    let root = tempfile::tempdir().unwrap();
    let child = root.path().join("child");
    std::fs::create_dir(&child).unwrap();
    let result = dispatch(root.path(), "worklist:rank", json!({"target":"child"})).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(
        result["data"]["target"],
        std::fs::canonicalize(&child)
            .unwrap()
            .to_string_lossy()
            .as_ref()
    );
    assert!(!child.join(".kuzushi").exists());
}

#[test]
fn an_unimplemented_requested_contributor_is_an_explicit_error() {
    let root = tempfile::tempdir().unwrap();
    for name in ["includeFanIn", "include_fan_in", "fanIn"] {
        let error = dispatch(root.path(), "worklist:rank", json!({name:true})).unwrap_err();
        assert!(error.to_string().contains("not implemented"), "{error}");
    }
}

#[test]
fn coverage_limit_rejects_zero_negative_and_excessive_values() {
    let root = tempfile::tempdir().unwrap();
    for limit in [0, -1, 501] {
        assert!(dispatch(root.path(), "coverage:recommend", json!({"limit":limit})).is_err());
    }
}

#[test]
fn a_read_does_not_initialize_or_migrate_an_existing_coverage_database() {
    let root = tempfile::tempdir().unwrap();
    let path = kuzushi_core::workspace::coverage_ledger::workspace_coverage_db_path(root.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE owned_sentinel(value TEXT);")
        .unwrap();
    drop(conn);
    let before = std::fs::read(&path).unwrap();
    let result = dispatch(root.path(), "coverage:recommend", json!({}));
    assert!(
        result.is_err(),
        "Uninitialized coverage must remain unavailable"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn child_recommendations_do_not_consume_parent_findings() {
    let root = tempfile::tempdir().unwrap();
    let child = root.path().join("child");
    std::fs::create_dir(&child).unwrap();
    write_surface_density(&child, "src/settings.rs");
    let ledger = kuzushi_core::workspace::coverage_ledger::CoverageLedger::open(&child).unwrap();
    ledger
        .record_baseline(&kuzushi_core::workspace::coverage_ledger::BaselineRow {
            scope_id: kuzushi_core::workspace::ROOT_SCOPE_ID.into(),
            phase: kuzushi_core::modules::WorkflowPhase::Scan,
            mode: "synthetic".into(),
            run_id: "owned-synthetic-baseline".into(),
            ts_unix: 1,
            revision: kuzushi_core::run_artifacts::RunTargetGitMetadata {
                sha: "synthetic-sha".into(),
                branch: None,
                dirty: false,
            },
        })
        .unwrap();
    drop(ledger);
    let store = kuzushi_core::findings::FindingStore::open_in_memory().unwrap();
    store
        .record_run_started("owned-parent-metadata", root.path(), "running")
        .unwrap();
    let finding = kuzushi_core::findings::Finding::new_tool(
        "owned-metadata",
        "owned-rule",
        "src/settings.rs",
        1,
        Some(1),
        kuzushi_core::Severity::Low,
        "Synthetic parent metadata",
    );
    store
        .insert_finding("owned-parent-metadata", &finding)
        .unwrap();
    let result = dispatch_with_store(
        root.path(),
        "worklist:rank",
        json!({"target":"child"}),
        Some(&store),
    )
    .unwrap();
    let citations = result["data"]["rows"][0]["citations"].as_array().unwrap();
    assert!(
        citations
            .iter()
            .any(|citation| citation["rawDisplay"] == "scan sink-gap"),
        "{result}"
    );
    assert!(!kuzushi_core::workspace::workspace_findings_db_path(&child).exists());
}

#[test]
fn excessive_coverage_history_is_a_failed_recommendation_and_a_degraded_worklist() {
    let root = tempfile::tempdir().unwrap();
    let ledger =
        kuzushi_core::workspace::coverage_ledger::CoverageLedger::open(root.path()).unwrap();
    drop(ledger);
    let path = kuzushi_core::workspace::coverage_ledger::workspace_coverage_db_path(root.path());
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    let transaction = conn.transaction().unwrap();
    transaction.execute_batch("WITH RECURSIVE history(ts) AS (VALUES(0) UNION ALL SELECT ts+1 FROM history WHERE ts<10000)
        INSERT INTO scan_baselines SELECT '.', 'scan', 'synthetic', 'owned-run', 'synthetic-sha', NULL, 0, ts FROM history;").unwrap();
    transaction.commit().unwrap();
    drop(conn);
    let error = dispatch(root.path(), "coverage:recommend", json!({})).unwrap_err();
    assert!(error.to_string().contains("10000-row read limit"));
    let result = dispatch(root.path(), "worklist:rank", json!({})).unwrap();
    assert!(result["data"]["degraded"]
        .to_string()
        .contains("10000-row read limit"));
    assert_eq!(result["data"]["rows"], json!([]));
}
