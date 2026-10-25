use super::*;
use crate::modules::WorkflowPhase;
use crate::run_artifacts::{RunSummary, RunTargetGitMetadata};
use std::fs;
use std::path::Path;
use std::process::Command;

mod cancellation;
mod history_reads;
mod read_only;
mod source_limits;
mod source_moves;
mod source_validity;

fn revision(sha: &str, dirty: bool) -> RunTargetGitMetadata {
    RunTargetGitMetadata {
        sha: sha.to_string(),
        branch: Some("main".to_string()),
        dirty,
    }
}

fn baseline(scope_id: &str, phase: WorkflowPhase, sha: &str, ts_unix: i64) -> BaselineRow {
    BaselineRow {
        scope_id: scope_id.to_string(),
        phase,
        mode: "default".to_string(),
        run_id: format!("run-{ts_unix}"),
        revision: revision(sha, false),
        ts_unix,
    }
}

fn workspace_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".kuzushi/v3")).unwrap();
    dir
}

#[test]
fn record_and_read_back_latest_baseline_per_scope_phase() {
    let dir = workspace_dir();
    let ledger = CoverageLedger::open(dir.path()).unwrap();
    ledger
        .record_baseline(&baseline("root", WorkflowPhase::Scan, "aaa", 100))
        .unwrap();
    ledger
        .record_baseline(&baseline("root", WorkflowPhase::Scan, "bbb", 200))
        .unwrap();
    ledger
        .record_baseline(&baseline("root", WorkflowPhase::Map, "aaa", 150))
        .unwrap();

    let latest = ledger.latest_baselines().unwrap();

    assert_eq!(latest.len(), 2);
    let scan = latest
        .iter()
        .find(|row| row.phase == WorkflowPhase::Scan)
        .unwrap();
    assert_eq!(scan.revision.sha, "bbb");
    assert_eq!(scan.ts_unix, 200);
}

#[test]
fn ledger_survives_reopen() {
    let dir = workspace_dir();
    CoverageLedger::open(dir.path())
        .unwrap()
        .record_baseline(&baseline("root", WorkflowPhase::Scan, "aaa", 100))
        .unwrap();

    let rows = CoverageLedger::open(dir.path())
        .unwrap()
        .all_baselines()
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].revision.sha, "aaa");
    assert!(!rows[0].revision.dirty);
}

fn summary(status: &str, tool: Option<&str>, git: Option<RunTargetGitMetadata>) -> RunSummary {
    let mut summary = RunSummary::running("run-1", "tool", tool.map(str::to_string), "/tmp/target");
    summary.status = status.to_string();
    summary.target_git = git;
    summary.completed_at_unix = Some(500);
    summary
}

#[test]
fn completed_scan_tool_summary_records_baseline() {
    let dir = workspace_dir();
    let recorded = record_baseline_from_summary(
        dir.path(),
        &summary("completed", Some("sast:scan"), Some(revision("abc", false))),
    )
    .unwrap();

    let row = recorded.expect("baseline should be recorded");
    assert_eq!(row.phase, WorkflowPhase::Scan);
    assert_eq!(row.scope_id, "root");
    assert_eq!(row.ts_unix, 500);
    assert_eq!(
        CoverageLedger::open(dir.path())
            .unwrap()
            .all_baselines()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn failed_or_provenance_free_summaries_record_nothing() {
    let dir = workspace_dir();
    let failed = summary("failed", Some("sast:scan"), Some(revision("abc", false)));
    let no_git = summary("completed", Some("sast:scan"), None);

    assert!(record_baseline_from_summary(dir.path(), &failed)
        .unwrap()
        .is_none());
    assert!(record_baseline_from_summary(dir.path(), &no_git)
        .unwrap()
        .is_none());
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

fn temp_git_workspace() -> Option<tempfile::TempDir> {
    if Command::new("git").arg("--version").output().is_err() {
        return None;
    }
    let dir = workspace_dir();
    git(dir.path(), &["init"]);
    git(dir.path(), &["checkout", "-b", "main"]);
    git(dir.path(), &["config", "user.email", "test@example.com"]);
    git(dir.path(), &["config", "user.name", "Kuzushi Test"]);
    commit_file(dir.path(), "src/lib.rs", "initial\n", "initial");
    Some(dir)
}

fn commit_file(target: &Path, rel_path: &str, contents: &str, message: &str) {
    let path = target.join(rel_path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, contents).unwrap();
    git(target, &["add", "."]);
    git(
        target,
        &["-c", "commit.gpgsign=false", "commit", "-m", message],
    );
}

fn head_sha(target: &Path) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(target)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

#[test]
fn sweep_reports_changed_current_and_unreachable() {
    let Some(dir) = temp_git_workspace() else {
        return;
    };
    let first = head_sha(dir.path());
    let ledger = CoverageLedger::open(dir.path()).unwrap();
    ledger
        .record_baseline(&baseline("root", WorkflowPhase::Scan, &first, 100))
        .unwrap();
    ledger
        .record_baseline(&baseline("root", WorkflowPhase::Map, "0000dead", 90))
        .unwrap();
    commit_file(dir.path(), "src/new.rs", "new\n", "second");

    let report = sweep_target(dir.path()).unwrap();

    let scan = entry(&report, WorkflowPhase::Scan);
    assert_eq!(scan.verdict, SweepVerdict::Changed { files: 1 });
    let map = entry(&report, WorkflowPhase::Map);
    assert_eq!(map.verdict, SweepVerdict::BaselineUnreachable);
}

#[test]
fn sweep_marks_head_baseline_current_and_write_skips_advances_others() {
    let Some(dir) = temp_git_workspace() else {
        return;
    };
    let first = head_sha(dir.path());
    let ledger = CoverageLedger::open(dir.path()).unwrap();
    ledger
        .record_baseline(&baseline("root", WorkflowPhase::Scan, &first, 100))
        .unwrap();
    commit_file(dir.path(), "docs/readme.md", "docs only\n", "docs change");
    let second = head_sha(dir.path());

    // The whole tree is the root scope, so the docs commit counts as change.
    let report = sweep_target(dir.path()).unwrap();
    assert_eq!(
        entry(&report, WorkflowPhase::Scan).verdict,
        SweepVerdict::Changed { files: 1 }
    );

    // A baseline already at HEAD is current and needs no skip row.
    ledger
        .record_baseline(&baseline("root", WorkflowPhase::Scan, &second, 200))
        .unwrap();
    let report = sweep_target(dir.path()).unwrap();
    assert_eq!(
        entry(&report, WorkflowPhase::Scan).verdict,
        SweepVerdict::Current
    );
    assert_eq!(write_sweep_skips(dir.path(), &report).unwrap(), 0);
}

#[test]
fn write_skips_records_sweep_skip_rows_at_head_for_unchanged_scopes() {
    let Some(dir) = temp_git_workspace() else {
        return;
    };
    let first = head_sha(dir.path());
    save_scope_tree(dir.path(), &[("root", "."), ("sub-docs", "docs")]);
    let ledger = CoverageLedger::open(dir.path()).unwrap();
    ledger
        .record_baseline(&baseline("sub-docs", WorkflowPhase::Scan, &first, 100))
        .unwrap();
    commit_file(dir.path(), "src/other.rs", "code\n", "code change");
    let second = head_sha(dir.path());

    let report = sweep_target(dir.path()).unwrap();
    let docs = entry(&report, WorkflowPhase::Scan);
    assert_eq!(docs.verdict, SweepVerdict::Current);

    assert_eq!(write_sweep_skips(dir.path(), &report).unwrap(), 1);
    let latest = ledger.latest_baselines().unwrap();
    let advanced = latest
        .iter()
        .find(|row| row.scope_id == "sub-docs")
        .unwrap();
    assert_eq!(advanced.revision.sha, second);
    assert_eq!(advanced.mode, SWEEP_SKIP_MODE);
    assert_eq!(advanced.run_id, SWEEP_RUN_ID);
}

#[test]
fn write_skips_refuses_dirty_tree() {
    let Some(dir) = temp_git_workspace() else {
        return;
    };
    let first = head_sha(dir.path());
    CoverageLedger::open(dir.path())
        .unwrap()
        .record_baseline(&baseline("root", WorkflowPhase::Scan, &first, 100))
        .unwrap();
    commit_file(dir.path(), "docs/readme.md", "docs\n", "second");
    fs::write(dir.path().join("src/lib.rs"), "dirty\n").unwrap();

    let report = sweep_target(dir.path()).unwrap();
    let error = write_sweep_skips(dir.path(), &report).unwrap_err();

    assert!(error.to_string().contains("dirty"));
}

fn entry(report: &SweepReport, phase: WorkflowPhase) -> &ScopeSweepEntry {
    report
        .entries
        .iter()
        .find(|entry| entry.phase == phase)
        .unwrap()
}

fn save_scope_tree(target: &Path, scopes: &[(&str, &str)]) {
    let tree = crate::workspace::NestedProjectScopeTree {
        schema_version: 1,
        root: "root".to_string(),
        scopes: scopes
            .iter()
            .map(|(id, rel_path)| crate::workspace::NestedProjectScope {
                id: id.to_string(),
                parent: (*id != "root").then(|| "root".to_string()),
                kind: if *id == "root" {
                    crate::workspace::NestedProjectKind::Root
                } else {
                    crate::workspace::NestedProjectKind::Submodule
                },
                rel_path: rel_path.to_string(),
                inherited_sections: Vec::new(),
            })
            .collect(),
    };
    crate::workspace::save_nested_project_scopes(target, &tree).unwrap();
}

fn guard(file: &str, line: u32) -> GuardRow {
    GuardRow {
        file: file.to_string(),
        line,
        guard: "bounds check dominates the memcpy".to_string(),
        protects: "wire length into snapshot_buf".to_string(),
        bypass_result: "bypass refuted: both callers clamp".to_string(),
        revision_sha: "abc123".to_string(),
        file_hash: String::new(), // computed at record time
        ts_unix: 100,
    }
}

#[test]
fn guards_survive_while_the_file_is_unchanged_and_expire_on_edit() {
    let dir = workspace_dir();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/a.c"), "guarded contents\n").unwrap();
    let ledger = CoverageLedger::open(dir.path()).unwrap();
    ledger
        .record_guard(dir.path(), &guard("src/a.c", 100))
        .unwrap();

    let (active, expired) = ledger.active_guards(dir.path()).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(expired, 0);

    fs::write(dir.path().join("src/a.c"), "changed contents\n").unwrap();
    let (active, expired) = ledger.active_guards(dir.path()).unwrap();
    assert!(active.is_empty(), "a changed file must kill its guard rows");
    assert_eq!(expired, 1);
}

#[test]
fn fresh_findings_inside_a_live_guard_window_are_conflicts() {
    let dir = workspace_dir();
    fs::create_dir_all(dir.path().join("src")).unwrap();
    fs::write(dir.path().join("src/a.c"), "guarded contents\n").unwrap();
    let ledger = CoverageLedger::open(dir.path()).unwrap();
    ledger
        .record_guard(dir.path(), &guard("src/a.c", 100))
        .unwrap();
    let (active, _) = ledger.active_guards(dir.path()).unwrap();

    assert!(guard_conflict(&active, "src/a.c", 110).is_some());
    assert!(guard_conflict(&active, "src/a.c", 130).is_none());
    assert!(guard_conflict(&active, "src/b.c", 100).is_none());
}
