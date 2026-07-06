use super::*;
use kuzushi_core::write_run_summary;

#[test]
fn source_file_cache_refreshes_when_size_changes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("src.rs");
    std::fs::write(&path, "one").unwrap();
    let mut cache = WorkbenchCache::default();

    assert_eq!(cache.read_source_file(&path).unwrap(), "one");
    std::fs::write(&path, "two lines").unwrap();

    assert_eq!(cache.read_source_file(&path).unwrap(), "two lines");
}

#[test]
fn run_summary_cache_refreshes_when_scan_ids_change() {
    let temp = tempfile::tempdir().unwrap();
    let mut cache = WorkbenchCache::default();
    assert!(cache
        .run_summary_index(Some(temp.path()), Vec::new())
        .is_empty());

    let summary = RunSummary::running("scan-a", "scan", None, "target");
    write_run_summary(temp.path(), &summary).unwrap();

    let indexed = cache.run_summary_index(Some(temp.path()), vec!["scan-a".to_string()]);
    assert!(indexed.contains_key("scan-a"));
}

#[test]
fn project_scope_tree_does_not_discover_on_cache_miss() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("libs/parser/.git")).unwrap();
    std::fs::write(
        temp.path().join(".gitmodules"),
        r#"
            [submodule "libs/parser"]
                path = libs/parser
            "#,
    )
    .unwrap();
    let mut cache = WorkbenchCache::default();

    let state = cache.project_scope_tree(Some(temp.path())).unwrap();

    assert_eq!(state, ProjectScopeTreeState::RootOnly);
}

#[test]
fn project_scope_tree_reads_persisted_scope_map() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("libs/parser/.git")).unwrap();
    std::fs::write(
        temp.path().join(".gitmodules"),
        r#"
            [submodule "libs/parser"]
                path = libs/parser
            "#,
    )
    .unwrap();
    let tree = kuzushi_core::discover_nested_project_scopes(temp.path());
    kuzushi_core::save_nested_project_scopes(temp.path(), &tree).unwrap();
    let mut cache = WorkbenchCache::default();

    let state = cache.project_scope_tree(Some(temp.path())).unwrap();

    assert!(matches!(state, ProjectScopeTreeState::Persisted(_)));
}
