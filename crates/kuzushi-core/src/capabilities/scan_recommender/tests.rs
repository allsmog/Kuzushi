use super::*;
use crate::modules::WorkflowPhase;
use crate::run_artifacts::RunTargetGitMetadata;
use crate::workspace::coverage_ledger::{BaselineRow, ScopeSweepEntry, SweepReport, SweepVerdict};
use std::collections::{BTreeMap, BTreeSet};

fn revision(sha: &str) -> RunTargetGitMetadata {
    RunTargetGitMetadata {
        sha: sha.to_string(),
        branch: Some("main".to_string()),
        dirty: false,
    }
}

fn baseline(scope_id: &str, phase: WorkflowPhase, sha: &str, ts_unix: i64) -> BaselineRow {
    BaselineRow {
        scope_id: scope_id.to_string(),
        phase,
        mode: "default".to_string(),
        run_id: format!("run-{ts_unix}"),
        revision: revision(sha),
        ts_unix,
    }
}

fn sweep_with(entries: Vec<ScopeSweepEntry>) -> SweepReport {
    SweepReport {
        head: revision("headhead"),
        entries,
        unbaselined_scopes: Vec::new(),
    }
}

fn scope_paths(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(id, path)| (id.to_string(), path.to_string()))
        .collect()
}

#[test]
fn unscanned_scope_ranks_first_as_never_scanned() {
    let scopes = scope_paths(&[("root", "."), ("sub-a", "a")]);
    let baselines = vec![baseline("root", WorkflowPhase::Scan, "headhead", 100)];
    let inputs = RecommenderInputs {
        scope_paths: &scopes,
        latest_baselines: &baselines,
        all_baselines: &baselines,
        sweep: None,
        surface_files: &BTreeMap::new(),
        finding_files: &BTreeSet::new(),
    };

    let rows = recommend(&inputs);

    assert_eq!(rows[0].scope_id, "sub-a");
    assert_eq!(rows[0].reason, ReasonTag::NeverScanned);
    assert_eq!(rows[0].phase, WorkflowPhase::Scan);
}

#[test]
fn mapped_but_unscanned_scope_is_a_phase_gap() {
    let scopes = scope_paths(&[("root", ".")]);
    let baselines = vec![baseline("root", WorkflowPhase::Map, "headhead", 100)];
    let inputs = RecommenderInputs {
        scope_paths: &scopes,
        latest_baselines: &baselines,
        all_baselines: &baselines,
        sweep: None,
        surface_files: &BTreeMap::new(),
        finding_files: &BTreeSet::new(),
    };

    let rows = recommend(&inputs);

    assert_eq!(rows[0].reason, ReasonTag::PhaseGap);
}

#[test]
fn changed_sweep_entry_scores_with_file_volume_and_evidence() {
    let scopes = scope_paths(&[("root", ".")]);
    let baselines = vec![baseline("root", WorkflowPhase::Scan, "aaaabbbb", 100)];
    let sweep = sweep_with(vec![ScopeSweepEntry {
        scope_id: "root".to_string(),
        phase: WorkflowPhase::Scan,
        baseline_sha: "aaaabbbbcccc".to_string(),
        baseline_dirty: false,
        verdict: SweepVerdict::Changed { files: 14 },
    }]);
    let inputs = RecommenderInputs {
        scope_paths: &scopes,
        latest_baselines: &baselines,
        all_baselines: &baselines,
        sweep: Some(&sweep),
        surface_files: &BTreeMap::new(),
        finding_files: &BTreeSet::new(),
    };

    let rows = recommend(&inputs);

    let changed = rows
        .iter()
        .find(|row| row.reason == ReasonTag::Changed)
        .unwrap();
    assert!(changed
        .evidence
        .contains("14 file(s) changed since aaaabbbb"));
    assert!(changed.score > 0.5 && changed.score < 0.9);
}

#[test]
fn surface_files_without_findings_recommend_sink_gap_mode() {
    let scopes = scope_paths(&[("root", "."), ("sub-net", "net")]);
    let baselines = vec![
        baseline("root", WorkflowPhase::Scan, "headhead", 100),
        baseline("sub-net", WorkflowPhase::Scan, "headhead", 100),
    ];
    let surface_files = BTreeMap::from([
        ("net/server.c".to_string(), 3),
        ("net/parse.c".to_string(), 2),
        ("cli/main.c".to_string(), 1),
    ]);
    let finding_files = BTreeSet::from(["net/server.c".to_string()]);
    let inputs = RecommenderInputs {
        scope_paths: &scopes,
        latest_baselines: &baselines,
        all_baselines: &baselines,
        sweep: None,
        surface_files: &surface_files,
        finding_files: &finding_files,
    };

    let rows = recommend(&inputs);

    let net_gap = rows
        .iter()
        .find(|row| row.reason == ReasonTag::SinkGap && row.scope_id == "sub-net")
        .unwrap();
    assert_eq!(net_gap.suggested_mode.as_deref(), Some("sink-gap"));
    assert!(net_gap.evidence.contains("1 of 2"));
}

#[test]
fn repeated_baseline_records_cannot_establish_scan_saturation() {
    let scopes = scope_paths(&[("root", ".")]);
    let all = vec![
        baseline("root", WorkflowPhase::Scan, "headhead", 100),
        baseline("root", WorkflowPhase::Scan, "headhead", 200),
    ];
    let latest = vec![all[1].clone()];
    let sweep = sweep_with(vec![]);
    let inputs = RecommenderInputs {
        scope_paths: &scopes,
        latest_baselines: &latest,
        all_baselines: &all,
        sweep: Some(&sweep),
        surface_files: &BTreeMap::new(),
        finding_files: &BTreeSet::new(),
    };

    let rows = recommend(&inputs);

    assert!(
        rows.is_empty(),
        "history alone proposed extra work: {rows:?}"
    );
}
