use super::*;

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
fn git_head_absorbs_file_level_work() {
    let changes = coalesce_changes([
        WorkspaceChange::FileChanged("src/main.rs".into()),
        WorkspaceChange::GitHeadChanged,
        WorkspaceChange::GitIndexChanged,
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

fn projected_indexed_file_count(db_path: &Path, snapshot_hash: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.query_row(
        "select count(*) from indexed_files where snapshot_hash = ?1",
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
