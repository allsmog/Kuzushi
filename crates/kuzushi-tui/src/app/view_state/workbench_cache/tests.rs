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

/// `Ready` scan receipts describe terminal runs and never change on disk, so
/// every invalidation path keeps them; only unsettled `Missing`/`Failed`
/// entries re-read. Dropping settled receipts made the Scan page flap to its
/// legacy projection on each external workspace refresh.
#[test]
fn settled_scan_receipts_survive_cache_invalidation() {
    let target = PathBuf::from("/tmp/receipt-cache-target");
    let mut cache = WorkbenchCache::default();
    seed_scan_receipt(&mut cache, &target, "run-ready", ready_receipt_state());
    seed_scan_receipt(
        &mut cache,
        &target,
        "run-missing",
        ScanStageReceiptState::Missing,
    );

    cache.invalidate_state_artifact_paths(
        &target,
        &[
            PathBuf::from(".kuzushi/v3/runs/run-ready/done.json"),
            PathBuf::from(".kuzushi/v3/runs/run-missing/done.json"),
        ],
    );
    assert!(matches!(
        cache.cached_scan_stage_receipt(&target, "run-ready"),
        ViewDataState::Ready(ScanStageReceiptState::Ready(_))
    ));
    assert!(cache
        .cached_scan_stage_receipt(&target, "run-missing")
        .is_not_requested());

    seed_scan_receipt(
        &mut cache,
        &target,
        "run-missing",
        ScanStageReceiptState::Missing,
    );
    cache.invalidate_state_artifact_paths(&target, &[PathBuf::from(".kuzushi/v3")]);
    cache.invalidate_workspace_files();
    cache.invalidate_run_summaries();

    assert!(matches!(
        cache.cached_scan_stage_receipt(&target, "run-ready"),
        ViewDataState::Ready(ScanStageReceiptState::Ready(_))
    ));
    assert!(cache
        .cached_scan_stage_receipt(&target, "run-missing")
        .is_not_requested());
}

/// Invalidation marks the entries index stale instead of dropping it: the
/// previous entries keep serving (no empty-index frame on durable pages)
/// while the hydration gate reports a refresh is due.
#[test]
fn stale_run_summary_entries_serve_until_rehydrated() {
    let target = PathBuf::from("/tmp/entries-cache-target");
    let mut cache = WorkbenchCache::default();
    let entry = RunSummaryEntry {
        run_id: "scan-run".to_string(),
        path: target.join(".kuzushi/v3/runs/scan-run/summary.json"),
        state: kuzushi_core::RunSummaryEntryState::Ready(RunSummary::running(
            "scan-run", "scan", None, "target",
        )),
    };
    cache.apply_view_hydration(ViewHydrationResult {
        target: target.clone(),
        key: ViewHydrationKey::RunSummaryEntries,
        value: ViewHydrationValue::RunSummaryEntries(RunSummaryEntriesState::Ready(vec![entry])),
    });
    assert!(!cache.run_summary_entries_need_refresh(&target));

    cache.invalidate_state_artifact_paths(&target, &[PathBuf::from(".kuzushi/v3")]);

    assert!(cache.run_summary_entries_need_refresh(&target));
    assert!(matches!(
        cache.cached_run_summary_entries(Some(&target)),
        ViewDataState::Ready(RunSummaryEntriesState::Ready(entries)) if entries.len() == 1
    ));
}

fn ready_receipt_state() -> ScanStageReceiptState {
    ScanStageReceiptState::Ready(kuzushi_core::run_artifacts::PhaseStageReceipt {
        phase: kuzushi_core::WorkflowPhase::Scan,
        outcome: kuzushi_core::run_artifacts::PhaseStageOutcome::Completed,
        run_refs: vec!["run-ready".to_string()],
        scan: None,
    })
}

fn seed_scan_receipt(
    cache: &mut WorkbenchCache,
    target: &Path,
    run_id: &str,
    state: ScanStageReceiptState,
) {
    cache.apply_view_hydration(ViewHydrationResult {
        target: target.to_path_buf(),
        key: ViewHydrationKey::ScanStageReceipt {
            run_id: run_id.to_string(),
        },
        value: ViewHydrationValue::ScanStageReceipt(state),
    });
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
