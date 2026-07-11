use super::*;
use notify::{
    event::{AccessKind, CreateKind, ModifyKind, RenameMode},
    Event, EventKind,
};
use std::process::Command;

#[test]
fn repeated_file_changes_keep_latest_state() {
    let changes = coalesce_changes([
        WorkspaceChange::FileChanged("src/main.rs".into()),
        WorkspaceChange::FileDeleted("src/main.rs".into()),
    ]);

    assert_eq!(
        changes,
        vec![WorkspaceChange::FileDeleted("src/main.rs".into())]
    );
}

#[test]
fn deleted_then_changed_file_keeps_latest_state() {
    let changes = coalesce_changes([
        WorkspaceChange::FileDeleted("src/main.rs".into()),
        WorkspaceChange::FileChanged("src/main.rs".into()),
    ]);

    assert_eq!(
        changes,
        vec![WorkspaceChange::FileChanged("src/main.rs".into())]
    );
}

#[test]
fn git_head_absorbs_file_level_work() {
    let changes = coalesce_changes([
        WorkspaceChange::FileChanged("src/main.rs".into()),
        WorkspaceChange::GitHeadChanged,
        WorkspaceChange::GitIndexChanged,
    ]);

    assert_eq!(changes, vec![WorkspaceChange::GitHeadChanged]);
}

#[test]
fn git_head_absorbs_later_file_level_work_in_same_batch() {
    let changes = coalesce_changes([
        WorkspaceChange::GitHeadChanged,
        WorkspaceChange::FileChanged("src/main.rs".into()),
        WorkspaceChange::FileDeleted("src/lib.rs".into()),
        WorkspaceChange::FileMoved {
            from: "src/old.rs".into(),
            to: "src/new.rs".into(),
        },
    ]);

    assert_eq!(changes, vec![WorkspaceChange::GitHeadChanged]);
}

#[test]
fn plans_source_and_policy_changes_differently() {
    assert_eq!(
        plan_for_change(&WorkspaceChange::FileChanged(
            "app/controllers/users.rs".into()
        )),
        ReindexPlan::FileFactsAndLocalAttackSurface
    );
    assert_eq!(
        plan_for_change(&WorkspaceChange::PromptOrHouseRuleChanged),
        ReindexPlan::MarkStaleOnly
    );
    assert!(should_ignore_path(Path::new(".kuzushi/v3/index.sqlite3")));
    assert!(should_ignore_path(Path::new(".kuzushi/codeql-db/db-cpp/default/cache")));
    assert!(should_ignore_path(Path::new(".git/HEAD")));
}

#[test]
fn full_snapshot_excludes_git_and_kuzushi_owned_state() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::write(temp.path().join("src/lib.rs"), "pub fn live() {}\n").unwrap();
    fs::create_dir_all(temp.path().join(".git/objects")).unwrap();
    fs::write(temp.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    let codeql = temp.path().join(".kuzushi/codeql-db/db-cpp/default/cache");
    fs::create_dir_all(codeql.parent().unwrap()).unwrap();
    fs::File::create(&codeql)
        .unwrap()
        .set_len(MAX_INDEXED_FILE_BYTES + 1)
        .unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();

    let snapshot = index_workspace_snapshot(&workspace).unwrap();

    assert_eq!(snapshot.files.len(), 1);
    assert_eq!(snapshot.files[0].path, "src/lib.rs");
}

#[test]
fn oversized_source_file_fails_before_unbounded_read() {
    let temp = tempfile::tempdir().unwrap();
    let oversized = temp.path().join("oversized.bin");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(MAX_INDEXED_FILE_BYTES + 1)
        .unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();

    let error = index_workspace_snapshot(&workspace).unwrap_err();

    assert!(error.to_string().contains("safety limit"));
    assert!(error.to_string().contains("oversized.bin"));
}

#[test]
fn snapshot_budget_rejects_excess_files_and_bytes() {
    let mut file_budget = IndexBudget {
        files: MAX_INDEXED_SNAPSHOT_FILES,
        bytes: 0,
    };
    assert!(file_budget.record(0).is_err());

    let mut byte_budget = IndexBudget {
        files: 0,
        bytes: MAX_INDEXED_SNAPSHOT_BYTES,
    };
    assert!(byte_budget.record(1).is_err());
}

#[test]
fn watcher_scope_includes_workspace_git_and_operator_policy_dirs() {
    let root = Path::new("/repo");
    let scope = workspace_watch_scope(root);

    assert_eq!(scope.root, PathBuf::from("/repo"));
    assert!(scope.roots.contains(&PathBuf::from("/repo")));
    assert!(scope.roots.contains(&PathBuf::from("/repo/.git")));
    assert!(scope.roots.contains(&PathBuf::from("/repo/.kuzushi/house-rules")));
    assert!(scope.roots.contains(&PathBuf::from("/repo/.kuzushi/prompts")));
}

#[test]
fn watcher_git_head_absorbs_ordinary_index_work() {
    let root = Path::new("/repo");
    let changes = classify_watcher_events(
        root,
        [
            WatchEvent::Modified("/repo/.git/HEAD".into()),
            WatchEvent::Modified("/repo/.git/index".into()),
            WatchEvent::Modified("/repo/package.json".into()),
            WatchEvent::Modified("/repo/pnpm-lock.yaml".into()),
            WatchEvent::Modified("/repo/src/routes/user.rs".into()),
        ],
    );

    assert_eq!(changes, vec![WorkspaceChange::GitHeadChanged]);
}

#[test]
fn watcher_classifies_policy_manifest_and_source_changes() {
    let root = Path::new("/repo");
    let changes = classify_watcher_events(
        root,
        [
            WatchEvent::Modified("/repo/.git/index".into()),
            WatchEvent::Modified("/repo/.kuzushi/prompts/sast/triage.md".into()),
            WatchEvent::Modified("/repo/.kuzushi/rules/sql.yml".into()),
            WatchEvent::Modified("/repo/package.json".into()),
            WatchEvent::Modified("/repo/pnpm-lock.yaml".into()),
            WatchEvent::Modified("/repo/src/routes/user.rs".into()),
        ],
    );

    assert_eq!(
        changes,
        vec![
            WorkspaceChange::FileChanged("src/routes/user.rs".into()),
            WorkspaceChange::ManifestChanged("package.json".into()),
            WorkspaceChange::LockfileChanged("pnpm-lock.yaml".into()),
            WorkspaceChange::GitIndexChanged,
            WorkspaceChange::RuleSetChanged,
            WorkspaceChange::PromptOrHouseRuleChanged,
        ]
    );
}

#[test]
fn watcher_ignores_v3_state_and_coalesces_batches() {
    let root = Path::new("/repo");
    let changes = classify_watcher_events(
        root,
        [
            WatchEvent::Modified("/repo/src/main.rs".into()),
            WatchEvent::Modified("/repo/.kuzushi/v3/index.sqlite3".into()),
            WatchEvent::Deleted("/repo/src/main.rs".into()),
        ],
    );

    assert_eq!(
        changes,
        vec![WorkspaceChange::FileDeleted("src/main.rs".into())]
    );
}

#[test]
fn watcher_ignores_owned_state_but_keeps_policy_signals() {
    let root = Path::new("/repo");
    let changes = classify_watcher_events(
        root,
        [
            WatchEvent::Modified("/repo/.kuzushi/codeql-db/db-cpp/cache".into()),
            WatchEvent::Modified("/repo/.kuzushi/prompts/sast/triage.md".into()),
            WatchEvent::Modified("/repo/.git/logs/HEAD".into()),
            WatchEvent::Modified("/repo/.git/index".into()),
        ],
    );

    assert_eq!(
        changes,
        vec![
            WorkspaceChange::GitIndexChanged,
            WorkspaceChange::PromptOrHouseRuleChanged,
        ]
    );
}

#[test]
fn state_aware_watcher_reports_v3_path_without_indexing_it() {
    let event = Event::new(EventKind::Modify(ModifyKind::Data(
        notify::event::DataChange::Any,
    )))
    .add_path("/repo/.kuzushi/v3/runs/run-1/trace.jsonl".into());

    let (changes, state_paths) = classify_notify_event_with_state(Path::new("/repo"), event);

    assert!(changes.is_empty());
    assert_eq!(
        state_paths,
        vec![PathBuf::from(
            ".kuzushi/v3/runs/run-1/trace.jsonl"
        )]
    );
}

#[test]
fn state_aware_watcher_reports_map_artifacts_without_codeql_churn() {
    let event = Event::new(EventKind::Modify(ModifyKind::Data(
        notify::event::DataChange::Any,
    )))
    .add_path("/repo/.kuzushi/context-snapshot.json".into())
    .add_path("/repo/.kuzushi/codeql-db".into())
    .add_path("/repo/.kuzushi/codeql-db/db-cpp/cache/chunk".into());

    let (changes, state_paths) = classify_notify_event_with_state(Path::new("/repo"), event);

    assert!(changes.is_empty());
    assert_eq!(
        state_paths,
        vec![
            PathBuf::from(".kuzushi/codeql-db"),
            PathBuf::from(".kuzushi/context-snapshot.json"),
        ]
    );
}

#[test]
fn watcher_classifies_moves_without_leaking_ignored_paths() {
    let root = Path::new("/repo");
    let changes = classify_watcher_events(
        root,
        [
            WatchEvent::Moved {
                from: "/repo/src/old.rs".into(),
                to: "/repo/src/new.rs".into(),
            },
            WatchEvent::Moved {
                from: "/repo/.kuzushi/v3/tmp".into(),
                to: "/repo/src/generated.rs".into(),
            },
            WatchEvent::Moved {
                from: "/repo/src/deleted.rs".into(),
                to: "/repo/.kuzushi/v3/deleted.rs".into(),
            },
        ],
    );

    assert_eq!(
        changes,
        vec![
            WorkspaceChange::FileChanged("src/generated.rs".into()),
            WorkspaceChange::FileDeleted("src/deleted.rs".into()),
            WorkspaceChange::FileMoved {
                from: "src/old.rs".into(),
                to: "src/new.rs".into(),
            },
        ]
    );
}

#[test]
fn notify_rename_event_maps_to_workspace_move() {
    let changes = classify_notify_event(
        Path::new("/repo"),
        Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path("/repo/src/old.rs".into())
            .add_path("/repo/src/new.rs".into()),
    );

    assert_eq!(
        changes,
        vec![WorkspaceChange::FileMoved {
            from: "src/old.rs".into(),
            to: "src/new.rs".into(),
        }]
    );
}

#[test]
fn notify_access_events_do_not_mark_workspace_stale() {
    let changes = classify_notify_event(
        Path::new("/repo"),
        Event::new(EventKind::Access(AccessKind::Read)).add_path("/repo/src/lib.rs".into()),
    );

    assert!(changes.is_empty());
}

#[test]
fn notify_create_events_use_existing_path_classification() {
    let changes = classify_notify_event(
        Path::new("/repo"),
        Event::new(EventKind::Create(CreateKind::File)).add_path("/repo/Cargo.toml".into()),
    );

    assert_eq!(
        changes,
        vec![WorkspaceChange::ManifestChanged("Cargo.toml".into())]
    );
}

#[test]
fn workspace_snapshot_indexes_files_through_cas_and_projection() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::create_dir_all(tmp.path().join(".kuzushi/v3")).unwrap();
    fs::write(tmp.path().join("src/app.rs"), "fn main() {}\n").unwrap();
    fs::write(tmp.path().join(".kuzushi/v3/cache.tmp"), "ignore me").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

    let indexed = index_workspace_snapshot(&workspace).unwrap();

    assert_eq!(indexed.file_count, 1);
    assert_eq!(indexed.applied_seq, 2);
    assert!(workspace.objects_dir().join("blake3").is_dir());
    assert_eq!(
        projected_indexed_file_count(&workspace.findings_db_path(), &indexed.snapshot_hash),
        1
    );
    assert_eq!(
        projected_indexed_language(&workspace.findings_db_path(), &indexed.snapshot_hash),
        "rust"
    );
}

#[test]
fn workspace_snapshot_records_git_metadata_and_dirty_hash() {
    let Some(repo) = temp_git_repo() else {
        return;
    };
    fs::write(repo.path().join("src/app.rs"), "fn main() { println!(\"dirty\"); }\n").unwrap();
    let head = git_stdout(repo.path(), &["rev-parse", "HEAD"]);
    let workspace = WorkspaceTarget::new(repo.path()).unwrap();

    let indexed = index_workspace_snapshot(&workspace).unwrap();

    let (commit, branch, dirty_hash) =
        projected_snapshot_git(&workspace.findings_db_path(), &indexed.snapshot_hash);
    assert_eq!(commit.as_deref(), Some(head.as_str()));
    assert_eq!(branch.as_deref(), Some("main"));
    assert!(dirty_hash.is_some());
}

#[test]
fn workspace_changes_incrementally_refresh_changed_file_facts() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/app.rs"), "fn main() {}\n").unwrap();
    fs::write(tmp.path().join("src/lib.rs"), "pub fn helper() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    let initial = index_workspace_snapshot(&workspace).unwrap();
    let original_app_blob =
        projected_indexed_blob(&workspace.findings_db_path(), &initial.snapshot_hash, "src/app.rs");
    let original_lib_blob =
        projected_indexed_blob(&workspace.findings_db_path(), &initial.snapshot_hash, "src/lib.rs");

    fs::write(tmp.path().join("src/app.rs"), "fn main() { println!(\"changed\"); }\n").unwrap();
    let update = index_workspace_changes(
        &workspace,
        &[WorkspaceChange::FileChanged("src/app.rs".into())],
    )
    .unwrap();

    let WorkspaceIndexUpdate::Incremental(updated) = update else {
        panic!("expected incremental update");
    };
    assert_ne!(updated.snapshot_hash, initial.snapshot_hash);
    assert_eq!(updated.file_count, 2);
    assert_eq!(
        projected_indexed_file_count(&workspace.findings_db_path(), &updated.snapshot_hash),
        2
    );
    assert_ne!(
        projected_indexed_blob(&workspace.findings_db_path(), &updated.snapshot_hash, "src/app.rs"),
        original_app_blob
    );
    assert_eq!(
        projected_indexed_blob(&workspace.findings_db_path(), &updated.snapshot_hash, "src/lib.rs"),
        original_lib_blob
    );
}

#[test]
fn workspace_changes_incrementally_records_deleted_file() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/app.rs"), "fn main() {}\n").unwrap();
    fs::write(tmp.path().join("src/lib.rs"), "pub fn helper() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
    index_workspace_snapshot(&workspace).unwrap();

    fs::remove_file(tmp.path().join("src/lib.rs")).unwrap();
    let update = index_workspace_changes(
        &workspace,
        &[WorkspaceChange::FileDeleted("src/lib.rs".into())],
    )
    .unwrap();

    let WorkspaceIndexUpdate::Incremental(updated) = update else {
        panic!("expected incremental update");
    };
    assert_eq!(updated.file_count, 1);
    assert_eq!(
        projected_indexed_file_count(&workspace.findings_db_path(), &updated.snapshot_hash),
        1
    );
    assert_eq!(
        projected_file_deletion_count(&workspace.findings_db_path(), &updated.snapshot_hash),
        1
    );
}

#[test]
fn workspace_changes_fall_back_to_full_snapshot_when_no_projection_exists() {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/app.rs"), "fn main() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

    let update = index_workspace_changes(
        &workspace,
        &[WorkspaceChange::FileChanged("src/app.rs".into())],
    )
    .unwrap();

    let WorkspaceIndexUpdate::Full(indexed) = update else {
        panic!("expected full snapshot fallback");
    };
    assert_eq!(indexed.file_count, 1);
}

#[test]
fn workspace_changes_record_dependency_invalidation_event() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

    let update = index_workspace_changes(
        &workspace,
        &[WorkspaceChange::ManifestChanged("Cargo.toml".into())],
    )
    .unwrap();

    let WorkspaceIndexUpdate::Invalidated {
        applied_seq,
        summary,
        ..
    } = update
    else {
        panic!("expected invalidation update");
    };
    assert_eq!(applied_seq, 1);
    assert!(summary.contains("dependency index marked stale"));
    assert_eq!(
        projected_audit_summary(&workspace.findings_db_path()),
        "dependency inputs changed; dependency index marked stale"
    );
}

#[test]
fn workspace_changes_record_ruleset_invalidation_event() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

    let update = index_workspace_changes(&workspace, &[WorkspaceChange::RuleSetChanged]).unwrap();

    let WorkspaceIndexUpdate::Invalidated { summary, .. } = update else {
        panic!("expected invalidation update");
    };
    assert!(summary.contains("deterministic scanner observations marked stale"));
    assert_eq!(projected_audit_count(&workspace.findings_db_path()), 1);
}

#[test]
fn workspace_changes_record_prompt_invalidation_event() {
    let tmp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

    let update =
        index_workspace_changes(&workspace, &[WorkspaceChange::PromptOrHouseRuleChanged]).unwrap();

    let WorkspaceIndexUpdate::Invalidated { summary, .. } = update else {
        panic!("expected invalidation update");
    };
    assert!(summary.contains("model-derived results marked stale"));
    assert_eq!(projected_audit_count(&workspace.findings_db_path()), 1);
}

fn projected_indexed_file_count(db_path: &Path, snapshot_hash: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "select count(*) from indexed_files where snapshot_hash = ?1",
        rusqlite::params![snapshot_hash],
        |row| row.get(0),
    )
    .unwrap()
}

fn projected_audit_summary(db_path: &Path) -> String {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "select summary from audit_events where subject = 'workspace-invalidation'",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn projected_audit_count(db_path: &Path) -> i64 {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "select count(*) from audit_events where subject = 'workspace-invalidation'",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn projected_indexed_blob(db_path: &Path, snapshot_hash: &str, path: &str) -> String {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "select blob_hash from indexed_files where snapshot_hash = ?1 and path = ?2",
        rusqlite::params![snapshot_hash, path],
        |row| row.get(0),
    )
    .unwrap()
}

fn projected_file_deletion_count(db_path: &Path, snapshot_hash: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "select count(*) from file_deletions where snapshot_hash = ?1",
        rusqlite::params![snapshot_hash],
        |row| row.get(0),
    )
    .unwrap()
}

fn projected_indexed_language(db_path: &Path, snapshot_hash: &str) -> String {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "select language from indexed_files where snapshot_hash = ?1 and path = 'src/app.rs'",
        rusqlite::params![snapshot_hash],
        |row| row.get(0),
    )
    .unwrap()
}

fn projected_snapshot_git(
    db_path: &Path,
    snapshot_hash: &str,
) -> (Option<String>, Option<String>, Option<String>) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "select git_commit, git_branch, dirty_hash from target_snapshots where snapshot_hash = ?1",
        rusqlite::params![snapshot_hash],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .unwrap()
}

fn temp_git_repo() -> Option<tempfile::TempDir> {
    if Command::new("git").arg("--version").output().is_err() {
        return None;
    }
    let repo = tempfile::tempdir().unwrap();
    fs::create_dir_all(repo.path().join("src")).unwrap();
    git(repo.path(), &["init"]);
    git(repo.path(), &["checkout", "-b", "main"]);
    git(repo.path(), &["config", "user.email", "test@example.com"]);
    git(repo.path(), &["config", "user.name", "Kuzushi Test"]);
    fs::write(repo.path().join("src/app.rs"), "fn main() {}\n").unwrap();
    git(repo.path(), &["add", "src/app.rs"]);
    git(
        repo.path(),
        &["-c", "commit.gpgsign=false", "commit", "-m", "initial"],
    );
    Some(repo)
}

fn git_stdout(target: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(target)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {} failed", args.join(" "));
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn git(target: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(target)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}
