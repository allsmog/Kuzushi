use super::gather::rank_worklist_observed;
use super::*;
use std::path::Path;

fn options(deep: bool) -> WorklistOptions {
    WorklistOptions {
        limit: 500,
        deep,
        include_fan_in: false,
    }
}
fn observed(root: &Path) -> super::gather::InspectedWorklist {
    rank_worklist_observed(root, &options(true), None, &mut |_| {}, None).unwrap()
}

#[test]
fn deep_ranking_honors_500_row_option_and_produces_no_graph_scan_or_finding() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("owned.c"),
        "// Owned parser packet length metadata. Never executed.\n",
    )
    .unwrap();
    let report = observed(root.path());
    assert_eq!(report.worklist.ranked_total, 1);
    assert!(report.worklist.rows[0]
        .citations
        .iter()
        .any(|row| row.contributor == Contributor::SystemsHunt));
    let receipt = report.systems_inspection.unwrap();
    assert_eq!(receipt["maxSourceFiles"], 2000);
    assert_eq!(receipt["maxFileBytes"], 16 * 1024);
    assert_eq!(receipt["completeRepositoryCoverage"], false);
    assert!(!root.path().join(".kuzushi/cpg-rs").exists());
    assert!(!crate::workspace::workspace_state_dir(root.path())
        .join("campaigns")
        .exists());
}

#[test]
fn default_ranking_does_not_walk_or_supply_systems_evidence() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("owned.c"),
        "// Owned parser packet metadata\n",
    )
    .unwrap();
    let report =
        rank_worklist_observed(root.path(), &options(false), None, &mut |_| {}, None).unwrap();
    assert!(report.systems_inspection.is_none());
    assert_eq!(
        report.worklist.contributors[&Contributor::SystemsHunt],
        ContributorState::NotRequested
    );
}

#[test]
fn deep_prefix_and_evidence_limits_are_partial_without_changing_source() {
    let root = tempfile::tempdir().unwrap();
    let text = "// Owned parser packet length metadata. Never executed.\n".repeat(2000);
    let path = root.path().join("owned.c");
    std::fs::write(&path, &text).unwrap();
    let report = observed(root.path());
    let receipt = report.systems_inspection.unwrap();
    assert_eq!(receipt["status"], "partial");
    assert_eq!(receipt["truncatedSourceFiles"], 1);
    assert_eq!(receipt["evidenceLimitedFiles"], 1);
    assert!(receipt["inspectedSourceBytes"].as_u64().unwrap() <= 16 * 1024);
    assert!(matches!(
        report.worklist.contributors[&Contributor::SystemsHunt],
        ContributorState::Degraded { .. }
    ));
    assert_eq!(std::fs::read_to_string(path).unwrap(), text);
}

#[cfg(unix)]
#[test]
fn deep_ranking_excludes_tests_symlink_cycles_and_outside_source() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("tests")).unwrap();
    for path in [
        root.path().join("owned.c"),
        root.path().join("tests/owned.c"),
        outside.path().join("outside.c"),
    ] {
        std::fs::write(path, "// Owned parser packet metadata\n").unwrap();
    }
    symlink(root.path(), root.path().join("cycle")).unwrap();
    symlink(
        outside.path().join("outside.c"),
        root.path().join("outside.c"),
    )
    .unwrap();
    let report = observed(root.path());
    assert_eq!(report.worklist.rows.len(), 1);
    assert_eq!(report.worklist.rows[0].path, "owned.c");
    let receipt = report.systems_inspection.unwrap();
    assert!(receipt["inventory"]["omittedPaths"].as_u64().unwrap() >= 2);
}

#[test]
fn deep_cancellation_during_inventory_stops_before_ranking() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("owned.c"), "// Owned parser\n").unwrap();
    let canceled = crate::ScanCancellation::default();
    let result = rank_worklist_observed(
        root.path(),
        &options(true),
        None,
        &mut |_| canceled.cancel(),
        Some(&canceled),
    );
    assert!(result.is_err());
    assert!(canceled.is_cancelled());
}

#[test]
fn deep_ranking_bounds_wide_repositories_at_the_actual_file_cap() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..2001 {
        std::fs::write(root.path().join(format!("owned-{index:04}.c")), "").unwrap();
    }
    let receipt = observed(root.path()).systems_inspection.unwrap();
    assert_eq!(receipt["attemptedFiles"], 2000);
    assert_eq!(receipt["omittedSourceFiles"], 1);
    assert_eq!(receipt["status"], "partial");
}
