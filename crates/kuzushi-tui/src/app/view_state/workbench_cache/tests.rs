use super::*;
use kuzushi_core::write_run_summary;

#[test]
fn source_file_cache_refreshes_after_workspace_invalidation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("src.rs");
    std::fs::write(&path, "one").unwrap();
    let mut cache = WorkbenchCache::default();

    assert_eq!(cache.read_source_file(&path).unwrap(), "one");
    std::fs::write(&path, "two lines").unwrap();
    cache.invalidate_workspace_files();

    assert_eq!(cache.read_source_file(&path).unwrap(), "two lines");
}

#[test]
fn harness_file_serves_cached_contents_until_invalidated() {
    let temp = tempfile::tempdir().unwrap();
    let path = seed_harness_file(temp.path(), "raw = \"auth\"");
    let mut cache = WorkbenchCache::default();

    assert_eq!(
        cache.harness_file(Some(temp.path())).as_deref(),
        Some("raw = \"auth\"")
    );

    std::fs::write(&path, "raw = \"api!\"").unwrap();

    let served = cache.harness_file(Some(temp.path()));
    assert_eq!(served.as_deref(), Some("raw = \"auth\""));
}

#[test]
fn harness_file_refreshes_after_workspace_invalidation() {
    let temp = tempfile::tempdir().unwrap();
    let path = seed_harness_file(temp.path(), "raw = \"auth\"");
    let mut cache = WorkbenchCache::default();
    assert_eq!(
        cache.harness_file(Some(temp.path())).as_deref(),
        Some("raw = \"auth\"")
    );

    std::fs::write(&path, "raw = \"payments\"").unwrap();
    cache.invalidate_workspace_files();

    assert_eq!(
        cache.harness_file(Some(temp.path())).as_deref(),
        Some("raw = \"payments\"")
    );
}

#[test]
fn harness_file_is_none_when_target_unset_or_not_seeded() {
    let temp = tempfile::tempdir().unwrap();
    let mut cache = WorkbenchCache::default();

    assert_eq!(cache.harness_file(None), None);
    assert_eq!(cache.harness_file(Some(temp.path())), None);
}

fn seed_harness_file(target: &Path, contents: &str) -> PathBuf {
    let path = harness_file_path(target);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn run_summary_cache_refreshes_after_run_persistence() {
    let temp = tempfile::tempdir().unwrap();
    let mut cache = WorkbenchCache::default();
    assert!(cache
        .run_summary_index(Some(temp.path()), Vec::new())
        .is_empty());

    let summary = RunSummary::running("scan-a", "scan", None, "target");
    write_run_summary(temp.path(), &summary).unwrap();
    cache.invalidate_run_summaries();

    let indexed = cache.run_summary_index(Some(temp.path()), vec!["scan-a".to_string()]);
    assert!(indexed.contains_key("scan-a"));
}

#[test]
fn latest_run_pointer_refreshes_after_run_persistence_invalidation() {
    let temp = tempfile::tempdir().unwrap();
    let mut cache = WorkbenchCache::default();
    assert_eq!(
        cache.latest_run_pointer(Some(temp.path())),
        LatestRunPointerState::Missing
    );

    let summary = RunSummary::running("scan-latest", "scan", None, "target");
    write_run_summary(temp.path(), &summary).unwrap();
    assert_eq!(
        cache.latest_run_pointer(Some(temp.path())),
        LatestRunPointerState::Missing
    );

    cache.invalidate_run_summaries();
    assert!(matches!(
        cache.latest_run_pointer(Some(temp.path())),
        LatestRunPointerState::Ready(ref run_id) if run_id.as_str() == "scan-latest"
    ));
}

#[test]
fn run_projection_cache_is_bounded_and_keeps_the_new_entry() {
    let target = Path::new("/target");
    let mut cache = WorkbenchCache::default();
    for index in 0..=MAX_LARGE_RUN_CACHE_ENTRIES {
        cache.store_run_projection(
            target.to_path_buf(),
            format!("run-{index:03}"),
            Err(format!("projection-{index}")),
        );
    }

    assert_eq!(cache.run_projections.len(), MAX_LARGE_RUN_CACHE_ENTRIES);
    assert!(matches!(
        cache.cached_run_projection(target, &format!("run-{MAX_LARGE_RUN_CACHE_ENTRIES:03}")),
        ViewDataState::Ready(Err(_))
    ));
}

#[test]
fn items_change_and_workspace_invalidation_evict_run_projection() {
    let target = tempfile::tempdir().unwrap();
    let mut cache = WorkbenchCache::default();
    cache.store_run_projection(
        target.path().to_path_buf(),
        "run-a".to_string(),
        Err("cached".to_string()),
    );
    let items = kuzushi_core::run_dir(target.path(), "run-a").join("items.jsonl");
    let relative = items.strip_prefix(target.path()).unwrap().to_path_buf();

    cache.invalidate_state_artifact_paths(target.path(), &[relative]);
    assert!(cache
        .cached_run_projection(target.path(), "run-a")
        .is_not_requested());

    cache.store_run_projection(
        target.path().to_path_buf(),
        "run-a".to_string(),
        Err("cached again".to_string()),
    );
    cache.invalidate_workspace_files();
    assert!(cache
        .cached_run_projection(target.path(), "run-a")
        .is_not_requested());
}

#[test]
fn bounded_map_never_discards_the_entry_being_inserted() {
    let mut entries = BTreeMap::new();
    for value in 0..=MAX_PATH_CACHE_ENTRIES {
        insert_bounded(&mut entries, value, value, MAX_PATH_CACHE_ENTRIES);
    }
    assert_eq!(entries.len(), MAX_PATH_CACHE_ENTRIES);
    assert_eq!(
        entries.get(&MAX_PATH_CACHE_ENTRIES),
        Some(&MAX_PATH_CACHE_ENTRIES)
    );
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
