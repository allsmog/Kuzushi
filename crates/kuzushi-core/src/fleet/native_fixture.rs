//! Owned, labeled observation records for exercising the real native readers.
use super::*;
use crate::findings::{Finding, FindingStore, Severity};
use crate::run_artifacts::{write_run_summary, RunSummary, RunTargetGitMetadata};
use std::path::Path;

fn record(store: &FindingStore, run: &str, rule: &str, file: &str, title: &str) {
    let mut finding = Finding::new_tool("owned-policy", rule, file, 1, None, Severity::Low, title);
    finding.scan_id = Some(run.into());
    store.insert_finding(run, &finding).unwrap();
}

fn run(root: &Path, store: &FindingStore, id: &str, sha: &str) {
    store.insert_scan_run(id, root, "completed").unwrap();
    let summary = RunSummary::running(
        id,
        "scan",
        Some("owned-policy:fixture".into()),
        root.display().to_string(),
    )
    .with_target_git(Some(RunTargetGitMetadata {
        sha: sha.into(),
        branch: Some("owned-labeled-metadata".into()),
        dirty: false,
    }))
    .complete();
    write_run_summary(root, &summary).unwrap();
}

fn prepare(root: &Path, base: &str, head: &str) {
    std::fs::create_dir_all(root.join(".kuzushi/v3")).unwrap();
    std::fs::write(
        root.join("package.json"),
        "{\"name\":\"owned-fleet-policy\",\"private\":true}\n",
    )
    .unwrap();
    let store = FindingStore::open(crate::workspace::workspace_findings_db_path(root)).unwrap();
    run(root, &store, "owned-base", base);
    run(root, &store, "owned-head", head);
    for (run, rule, file, title) in [
        (
            "owned-base",
            "shared-policy",
            "package.json",
            "Owned package policy observed at both labeled revisions",
        ),
        (
            "owned-base",
            "base-policy",
            "base-policy.txt",
            "Owned policy observed only in the base records; fix status remains unassessed",
        ),
        (
            "owned-head",
            "shared-policy",
            "package.json",
            "Owned package policy observed at both labeled revisions",
        ),
        (
            "owned-head",
            "head-policy",
            "head-policy.txt",
            "Owned policy observed only in the head records; introduction remains unassessed",
        ),
    ] {
        record(&store, run, rule, file, title);
    }
}

#[test]
fn native_fleet_history_fixture_preserves_recorded_presence() {
    let temporary = tempfile::tempdir().unwrap();
    let root = std::env::var_os("KUZUSHI_FLEET_FIXTURE_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().join("target"));
    let base = "a".repeat(40);
    let head = "b".repeat(40);
    prepare(&root, &base, &head);
    let fleet = tempfile::tempdir().unwrap();
    let target = FleetTarget {
        id: "owned".into(),
        path: root.clone(),
        remote: None,
        default_branch: None,
        label: Some("Owned labeled metadata".into()),
    };
    let report = rebuild_corpus(fleet.path(), &[target]).unwrap();
    assert_eq!(report.rows, 3);
    let comparison = diff_findings(fleet.path(), "owned", &base, &head).unwrap();
    assert_eq!(comparison.entries.len(), 3);
    let mut presence = comparison
        .entries
        .iter()
        .map(|entry| entry.lead.presence())
        .collect::<Vec<_>>();
    presence.sort();
    assert_eq!(presence, ["base-only", "both", "head-only"]);
    let manifest = serde_json::json!({"base":base,"head":head,"observations":4,"currentFindings":3,
        "revisionMetadataIsSynthetic":true,"sourceExecuted":false,"providerRequests":0});
    std::fs::write(
        root.join("fleet-fixture.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}
