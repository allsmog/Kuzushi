use super::*;
use crate::findings::Severity;
use std::process::Command;

const BASELINE: &str = "7cac9e253984e19ccc6aaeee3eb157de049ba667";
const LATER: &str = "c557cdbf94b931ecc250b33d33d793f79036a908";

fn git(root: &Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.autocrlf=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().into()
}

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let temp = tempfile::tempdir().unwrap();
    let bundle = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/owned-source-revisions.bundle")
        .canonicalize()
        .unwrap();
    git(
        temp.path(),
        &[
            "clone",
            "--quiet",
            "--no-hardlinks",
            "--branch",
            "main",
            bundle.to_str().unwrap(),
            "owned",
        ],
    );
    let workspace = WorkspaceTarget::new(temp.path().join("owned")).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(git(workspace.root(), &["rev-parse", "HEAD"]), BASELINE);
    (temp, workspace, store)
}

struct OwnedScanner {
    action: &'static str,
}
impl ScanEngine for OwnedScanner {
    fn id(&self) -> &'static str {
        "owned-source"
    }
    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        match self.action {
            "drift" => fs::write(
                target.join("README.md"),
                "Owned source changed during inspection.\n",
            )?,
            "cancel" => cancellation.cancel(),
            "interrupt" => cancellation.interrupt(),
            _ => (),
        }
        let file = if self.action == "missing" {
            "missing.md"
        } else {
            "README.md"
        };
        Ok(vec![Finding::new_tool(
            "owned-source",
            "greeting",
            file,
            1,
            None,
            Severity::Info,
            "Labeled source observation. No defect is claimed.",
        )])
    }
    fn scan_artifacts(
        &self,
        target: &Path,
        cancellation: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        Ok(ScanEngineOutput {
            findings: self.scan(target, cancellation)?,
            scan_errors: if self.action == "partial" {
                vec!["Owned uninspected path".into()]
            } else {
                Vec::new()
            },
            ..Default::default()
        })
    }
}

fn execute(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run: &str,
    action: &'static str,
) -> Result<NativeScanReport> {
    run_native_scan_with_cancellation(
        workspace,
        store,
        &[Box::new(OwnedScanner { action })],
        &ScanRunOptions {
            run_id: Some(run.into()),
            ..Default::default()
        },
        &Default::default(),
    )
}

fn recorded(store: &FindingStore) -> Vec<(Option<String>, Option<String>)> {
    let mut query = store.conn.prepare("select s.git_commit,o.blob_hash from finding_observations o left join target_snapshots s on s.snapshot_hash=o.snapshot_hash order by o.created_seq").unwrap();
    query
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn native_observations_keep_each_original_git_snapshot_and_source_blob_after_restart() {
    let (_temp, workspace, store) = fixture();
    let original = fs::read(workspace.root().join("README.md")).unwrap();
    execute(&workspace, &store, "baseline", "keep").unwrap();
    git(workspace.root(), &["checkout", "--quiet", LATER]);
    let later = fs::read(workspace.root().join("README.md")).unwrap();
    execute(&workspace, &store, "later", "keep").unwrap();
    assert_ne!(original, later);
    assert_eq!(store.list_all_findings().unwrap().len(), 1);
    let rows = recorded(&store);
    assert_eq!(
        rows.iter().map(|row| row.0.as_deref()).collect::<Vec<_>>(),
        vec![Some(BASELINE), Some(LATER)]
    );
    fs::write(workspace.root().join("README.md"), "Another owned edit.\n").unwrap();
    drop(store);
    let store = FindingStore::open_read_only(workspace.findings_db_path()).unwrap();
    for (row, expected) in rows.iter().zip([original, later]) {
        assert_eq!(
            store
                .read_observation_blob(row.1.as_ref().unwrap())
                .unwrap()
                .unwrap(),
            expected
        );
    }
    assert_eq!(recorded(&store), rows);
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}

#[test]
fn source_drift_retains_raw_observations_as_partial_without_inventing_snapshot_git() {
    let (_temp, workspace, store) = fixture();
    let report = execute(&workspace, &store, "drift", "drift").unwrap();
    assert_eq!(report.run.findings_count, 1);
    assert!(report.coverage.has_gaps());
    assert!(report
        .coverage
        .engine_detail("owned-source")
        .unwrap()
        .contains("Source changed"));
    assert_eq!(
        store.run_status("drift").unwrap().as_deref(),
        Some("partial")
    );
    assert_eq!(recorded(&store)[0].0, None);
}

#[test]
fn missing_source_retains_an_unbound_observation_with_an_explicit_coverage_gap() {
    let (_temp, workspace, store) = fixture();
    let report = execute(&workspace, &store, "missing", "missing").unwrap();
    assert_eq!(report.run.findings_count, 1);
    assert!(report.coverage.has_gaps());
    assert!(report
        .coverage
        .engine_detail("owned-source")
        .unwrap()
        .contains("source binding unavailable"));
    assert_eq!(recorded(&store)[0], (None, None));
}

#[test]
fn partial_engine_work_still_binds_retained_findings_to_the_original_source() {
    let (_temp, workspace, store) = fixture();
    let report = execute(&workspace, &store, "partial", "partial").unwrap();
    assert!(report.coverage.has_gaps());
    assert_eq!(
        store.run_status("partial").unwrap().as_deref(),
        Some("partial")
    );
    assert_eq!(recorded(&store)[0].0.as_deref(), Some(BASELINE));
}

#[test]
fn cancellation_and_interruption_keep_their_terminal_status_and_raw_observation() {
    for (action, status) in [("cancel", "canceled"), ("interrupt", "interrupted")] {
        let (_temp, workspace, store) = fixture();
        let error = execute(&workspace, &store, action, action).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<NativeScanFailure>()
                .unwrap()
                .report
                .run
                .findings_count,
            1
        );
        assert_eq!(store.run_status(action).unwrap().as_deref(), Some(status));
        assert_eq!(recorded(&store)[0], (None, None));
    }
}

#[test]
fn parent_snapshot_is_reused_without_replacing_it_after_source_changes() {
    let (_temp, workspace, store) = fixture();
    let config = crate::V2Config::default();
    let ctx = crate::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let source = crate::workspace::source_snapshot::SourceSnapshot::capture(
        &ctx,
        "owned-source",
        workspace.root(),
    )
    .unwrap();
    let first = run_native_scan_at_source(
        &workspace,
        &store,
        &[Box::new(OwnedScanner { action: "keep" })],
        &ScanRunOptions {
            run_id: Some("same-parent".into()),
            ..Default::default()
        },
        &Default::default(),
        Some(&source),
    )
    .unwrap();
    assert!(!first.coverage.has_gaps());
    let id = store.list_findings_for_scan_id("same-parent").unwrap()[0]
        .id
        .unwrap();
    assert_eq!(
        store
            .recorded_observation_source(id)
            .unwrap()
            .unwrap()
            .snapshot_hash,
        source.hashes().0
    );
    git(workspace.root(), &["checkout", "--quiet", LATER]);
    let later = run_native_scan_at_source(
        &workspace,
        &store,
        &[Box::new(OwnedScanner { action: "keep" })],
        &ScanRunOptions {
            run_id: Some("changed-parent".into()),
            ..Default::default()
        },
        &Default::default(),
        Some(&source),
    )
    .unwrap();
    assert!(later.coverage.has_gaps());
    assert_eq!(recorded(&store)[1], (None, None));
}

#[test]
fn adding_authenticated_source_does_not_fork_an_existing_legacy_finding_identity() {
    let (_temp, workspace, store) = fixture();
    let finding = OwnedScanner { action: "keep" }
        .scan(workspace.root(), &Default::default())
        .unwrap()
        .remove(0);
    store
        .record_run_started("legacy", workspace.root(), "completed")
        .unwrap();
    let old_id = store.insert_finding("legacy", &finding).unwrap();
    execute(&workspace, &store, "authenticated", "keep").unwrap();
    assert_eq!(store.list_all_findings().unwrap().len(), 1);
    assert_eq!(recorded(&store).len(), 2);
    assert_eq!(
        store
            .recorded_observation_source(old_id)
            .unwrap()
            .unwrap()
            .git_commit,
        None
    );
    assert_eq!(recorded(&store)[1].0.as_deref(), Some(BASELINE));
}
