use super::*;
use crate::findings::{Finding, FindingStore, Severity};
use std::fs;
use std::path::Path;

fn fleet_dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn target(id: &str, path: &Path) -> FleetTarget {
    FleetTarget {
        id: id.to_string(),
        path: path.to_path_buf(),
        remote: None,
        default_branch: Some("main".to_string()),
        label: None,
    }
}

#[test]
fn registry_roundtrips_and_reregistering_replaces_by_id() {
    let dir = fleet_dir();
    let workspace = fleet_dir();

    register_fleet_target(dir.path(), target("alpha", workspace.path())).unwrap();
    let updated = register_fleet_target(
        dir.path(),
        FleetTarget {
            label: Some("renamed".to_string()),
            ..target("alpha", workspace.path())
        },
    )
    .unwrap();

    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].label.as_deref(), Some("renamed"));
    assert_eq!(load_fleet_targets(dir.path()).unwrap(), updated);
}

#[test]
fn registry_rejects_blank_ids_and_relative_paths() {
    let dir = fleet_dir();

    assert!(register_fleet_target(dir.path(), target("", Path::new("/tmp"))).is_err());
    assert!(register_fleet_target(dir.path(), target("x", Path::new("relative"))).is_err());
}

fn workspace_with_findings(rows: &[(&str, u32, Severity, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".kuzushi/v3")).unwrap();
    let store =
        FindingStore::open(crate::workspace::workspace_findings_db_path(dir.path())).unwrap();
    store
        .insert_scan_run("scan-1", dir.path(), "running")
        .unwrap();
    for (index, (file, line, severity, title)) in rows.iter().enumerate() {
        // Distinct rule ids: tool fingerprints hash (tool, rule, file), and
        // the fixture needs distinct findings, not upserts of one.
        let mut finding = Finding::new_tool(
            "external-ledger",
            format!("mem-oob-write#{index}"),
            *file,
            *line,
            None,
            *severity,
            title.to_string(),
        );
        finding.scan_id = Some("scan-1".to_string());
        store.insert_finding("scan-1", &finding).unwrap();
    }
    dir
}

#[test]
fn corpus_rebuild_normalizes_rows_and_counts_quality_flags() {
    let fleet = fleet_dir();
    let workspace = workspace_with_findings(&[
        ("src/a.c", 100, Severity::Critical, "OOB write in parser"),
        ("src/a.c", 108, Severity::High, "OOB write adjacent"),
        ("src/b.c", 10, Severity::Low, "weird uncategorized thing"),
    ]);
    let targets = vec![target("t1", workspace.path())];

    let report = rebuild_corpus(fleet.path(), &targets).unwrap();

    assert_eq!(report.rows, 3);
    assert_eq!(report.targets_ingested, 1);
    // No run summaries exist in this fixture, so every row is flagged
    // no-revision — counted, never dropped.
    assert_eq!(report.quality_flag_count, 3);

    let rows = query_corpus_rows(fleet.path(), None, None, 10).unwrap();
    assert_eq!(rows.len(), 3);
    let clustered: Vec<_> = rows.iter().filter(|row| row.file == "src/a.c").collect();
    assert_eq!(clustered[0].cluster_id, clustered[1].cluster_id);
    assert!(rows
        .iter()
        .all(|row| row.quality_flags.contains("no-revision")));
}

#[test]
fn corpus_rebuild_is_a_swap_and_skips_unreachable_targets() {
    let fleet = fleet_dir();
    let workspace = workspace_with_findings(&[("src/a.c", 1, Severity::Info, "x")]);
    let targets = vec![
        target("good", workspace.path()),
        target("gone", Path::new("/nonexistent/fleet-target")),
    ];

    let report = rebuild_corpus(fleet.path(), &targets).unwrap();

    assert_eq!(report.targets_ingested, 1);
    assert_eq!(report.targets_skipped.len(), 1);
    assert!(report.targets_skipped[0].starts_with("gone:"));

    // A second rebuild replaces, not appends.
    let report = rebuild_corpus(fleet.path(), &targets).unwrap();
    assert_eq!(report.rows, 1);
}

#[test]
fn fleet_revision_comparison_retains_both_observations_of_one_identity() {
    use crate::run_artifacts::{write_run_summary, RunSummary, RunTargetGitMetadata};
    let fleet = fleet_dir();
    let workspace = fleet_dir();
    fs::create_dir_all(workspace.path().join(".kuzushi/v3")).unwrap();
    let store = FindingStore::open(crate::workspace::workspace_findings_db_path(
        workspace.path(),
    ))
    .unwrap();
    for (run, sha) in [
        ("owned-base", "a".repeat(40)),
        ("owned-head", "b".repeat(40)),
    ] {
        store
            .insert_scan_run(run, workspace.path(), "completed")
            .unwrap();
        let mut finding = Finding::new_tool(
            "owned-policy",
            "license-policy",
            "package.json",
            1,
            None,
            Severity::Low,
            "Owned package policy observation",
        );
        finding.scan_id = Some(run.into());
        store.insert_finding(run, &finding).unwrap();
        let summary = RunSummary::running(
            run,
            "scan",
            Some("license-scan:scan".into()),
            workspace.path().display().to_string(),
        )
        .with_target_git(Some(RunTargetGitMetadata {
            sha,
            branch: Some("owned".into()),
            dirty: false,
        }))
        .complete();
        write_run_summary(workspace.path(), &summary).unwrap();
    }
    rebuild_corpus(fleet.path(), &[target("owned", workspace.path())]).unwrap();
    let report = diff_findings(fleet.path(), "owned", &"a".repeat(40), &"b".repeat(40)).unwrap();
    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].lead, FindingLead::Both);
}

#[test]
fn fleet_status_folds_corpus_counts_and_ledger_baselines() {
    let fleet = fleet_dir();
    let workspace = workspace_with_findings(&[
        ("src/a.c", 100, Severity::Critical, "OOB write"),
        ("src/b.c", 10, Severity::High, "UAF"),
    ]);
    let targets = vec![target("t1", workspace.path())];
    rebuild_corpus(fleet.path(), &targets).unwrap();

    let report = fleet_status(fleet.path(), &targets).unwrap();

    assert_eq!(report.corpus_rows, 2);
    let status = &report.targets[0];
    assert!(status.reachable);
    assert_eq!(status.critical_open, 1);
    assert_eq!(status.high_open, 1);
    assert_eq!(status.baseline_count, 0);
}
