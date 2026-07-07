use super::*;
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
