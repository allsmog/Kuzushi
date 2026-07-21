use super::reader::FsViewArtifactReader;
use super::*;

fn map_state(target: &Path) -> bool {
    let ViewHydrationValue::MapArtifacts(built) =
        FsViewArtifactReader.read(target, &ViewHydrationKey::MapArtifacts)
    else {
        panic!("map hydration returned the wrong value type");
    };
    built
}

#[test]
fn map_hydration_rejects_a_directory_at_a_file_artifact_path() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join(".kuzushi/context-snapshot.json")).unwrap();

    assert!(!map_state(temp.path()));
}

#[cfg(unix)]
#[test]
fn map_hydration_rejects_symlinked_artifacts() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
    symlink(
        outside.path(),
        temp.path().join(".kuzushi/context-snapshot.json"),
    )
    .unwrap();

    assert!(!map_state(temp.path()));
}

#[cfg(unix)]
#[test]
fn map_hydration_rejects_a_symlinked_state_parent() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(
        outside.path().join("context-snapshot.json"),
        serde_json::json!({"filesIndexed": 1}).to_string(),
    )
    .unwrap();
    symlink(outside.path(), temp.path().join(".kuzushi")).unwrap();

    assert!(!map_state(temp.path()));
}

#[test]
fn map_hydration_accepts_an_indexed_source_context() {
    let temp = tempfile::tempdir().unwrap();
    let path = kuzushi_core::context_snapshot_path(temp.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::json!({"filesIndexed": 1}).to_string()).unwrap();

    assert!(map_state(temp.path()));
}

#[test]
fn map_hydration_rejects_an_evidence_empty_context_artifact() {
    let temp = tempfile::tempdir().unwrap();
    let path = kuzushi_core::context_snapshot_path(temp.path());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::json!({"filesIndexed": 0}).to_string()).unwrap();

    assert!(!map_state(temp.path()));
}

#[test]
fn mismatched_hydration_values_leave_the_key_retryable() {
    let temp = tempfile::tempdir().unwrap();
    let key = ViewHydrationKey::LatestRunPointer;
    let mut cache = WorkbenchCache::default();
    cache.mark_view_hydration_loading(temp.path(), std::slice::from_ref(&key));

    cache.apply_view_hydration(ViewHydrationResult {
        target: temp.path().to_path_buf(),
        key: key.clone(),
        value: ViewHydrationValue::TargetBase("wrong value".to_string()),
    });

    assert!(cache.view_hydration_needed(temp.path(), &key));
}

#[test]
fn source_hydration_rejects_paths_outside_the_target() {
    let target = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let value = FsViewArtifactReader.read(
        target.path(),
        &ViewHydrationKey::SourceFile {
            path: outside.path().to_path_buf(),
        },
    );

    let ViewHydrationValue::SourceFile(result) = value else {
        panic!("source hydration returned the wrong value type");
    };
    assert!(result.is_err());
}

#[test]
fn source_hydration_rejects_oversized_files() {
    let target = tempfile::tempdir().unwrap();
    let source = target.path().join("large.rs");
    let file = std::fs::File::create(&source).unwrap();
    file.set_len((2 * 1024 * 1024 + 1) as u64).unwrap();
    let value = FsViewArtifactReader.read(
        target.path(),
        &ViewHydrationKey::SourceFile { path: source },
    );

    let ViewHydrationValue::SourceFile(result) = value else {
        panic!("source hydration returned the wrong value type");
    };
    assert!(result.is_err());
}

#[test]
fn shell_construction_leaves_run_history_for_async_hydration() {
    let target = tempfile::tempdir().unwrap();
    let workspace = kuzushi_core::workspace::WorkspaceTarget::new(target.path()).unwrap();
    kuzushi_core::write_run_summary(
        target.path(),
        &kuzushi_core::RunSummary::running("run-async", "tool", None, "target").complete(),
    )
    .unwrap();

    let app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
    let state = app
        .workbench_cache()
        .borrow()
        .cached_run_summary_entries(Some(target.path()));

    assert_eq!(state, ViewDataState::NotRequested);
}

#[cfg(unix)]
#[test]
fn directory_hydration_rejects_symlinked_prompt_roots() {
    use std::os::unix::fs::symlink;

    let target = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret.md"), "secret").unwrap();
    let prompts = target.path().join(".kuzushi/prompts");
    std::fs::create_dir_all(&prompts).unwrap();
    let prompt_root = prompts.join("sast");
    symlink(outside.path(), &prompt_root).unwrap();
    let value = FsViewArtifactReader.read(
        target.path(),
        &ViewHydrationKey::DirectoryListing { path: prompt_root },
    );

    assert!(matches!(
        value,
        ViewHydrationValue::DirectoryListing(DirectoryListingState::Unreadable)
    ));
}

#[test]
fn scanned_snippet_hydration_slices_the_observation_blob_window() {
    let target = tempfile::tempdir().unwrap();
    let source_path = target.path().join("src/app.rs");
    std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
    std::fs::write(
        &source_path,
        "fn handler(term: &str) {\n    db.query(term);\n}\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
    let run_id = "run-scanned-snippet";
    store
        .record_run_started(run_id, target.path(), "running")
        .unwrap();
    let finding = kuzushi_core::Finding::new_tool(
        "semgrep",
        "rules.cwe-89",
        "src/app.rs",
        2,
        Some(2),
        kuzushi_core::Severity::High,
        "SQL injection reaches query builder, CWE-89",
    );
    store.insert_finding(run_id, &finding).unwrap();
    let stored = store.list_findings_for_scan_id(run_id).unwrap();
    let stable_fp = stored[0].identity_id.clone().unwrap();
    drop(store);

    let value = FsViewArtifactReader.read(
        target.path(),
        &ViewHydrationKey::ScannedSnippet {
            stable_fp,
            scan_id: Some(run_id.to_string()),
            focus_line: 2,
        },
    );

    let ViewHydrationValue::ScannedSnippet(ScannedSnippetState::Ready(window)) = value else {
        panic!("scanned snippet hydration returned the wrong state: {value:?}");
    };
    assert_eq!(window.focus_line, 2);
    assert_eq!(window.start_line, 1);
    assert_eq!(window.lines[1], "    db.query(term);");
}

#[test]
fn scanned_snippet_hydration_reports_missing_without_a_stored_blob() {
    let target = tempfile::tempdir().unwrap();

    let value = FsViewArtifactReader.read(
        target.path(),
        &ViewHydrationKey::ScannedSnippet {
            stable_fp: "unknown-identity".to_string(),
            scan_id: None,
            focus_line: 5,
        },
    );

    assert!(matches!(
        value,
        ViewHydrationValue::ScannedSnippet(ScannedSnippetState::Missing)
    ));
}
