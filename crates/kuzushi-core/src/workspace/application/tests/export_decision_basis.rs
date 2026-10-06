use super::*;
use crate::findings::{ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor};

fn observed(seq: u64, run: &str, snapshot: &str) -> ObservedSnapshot {
    ObservedSnapshot {
        created_seq: seq,
        run_id: run.into(),
        snapshot_hash: snapshot.into(),
    }
}

#[test]
fn decision_on_the_latest_observation_has_no_later_source() {
    let decided = observed(4, "run-a", "snap-1");
    let basis = basis(decided.clone(), Some(decided));
    assert_eq!(basis.run_id, "run-a");
    assert!(basis.later_observation.is_none());
    assert!(!basis.source_changed_since_decision);
}

#[test]
fn later_observation_on_changed_source_is_disclosed() {
    let basis = basis(
        observed(4, "run-a", "snap-1"),
        Some(observed(9, "run-b", "snap-2")),
    );
    assert_eq!(basis.later_observation.as_ref().unwrap().run_id, "run-b");
    assert!(basis.source_changed_since_decision);
}

#[test]
fn later_observation_on_identical_source_is_not_a_source_change() {
    let basis = basis(
        observed(4, "run-a", "snap-1"),
        Some(observed(9, "run-b", "snap-1")),
    );
    assert!(basis.later_observation.is_some());
    assert!(!basis.source_changed_since_decision);
}

fn labeled_finding() -> Finding {
    Finding::new_tool(
        "semgrep",
        "labeled.rule",
        "src/lib.rs",
        3,
        None,
        Severity::High,
        "Labeled fixture finding",
    )
}

fn confirm(store: &FindingStore, id: i64) {
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "labeled fixture decision".into(),
                dismiss_reason: None,
                actor: Some("operator".into()),
            },
        )
        .unwrap();
}

#[test]
fn export_names_the_run_a_decision_was_made_against() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-a", root.path(), "running")
        .unwrap();
    let id = store.insert_finding("run-a", &labeled_finding()).unwrap();
    confirm(&store, id);
    store
        .record_run_started("run-b", root.path(), "running")
        .unwrap();
    store.insert_finding("run-b", &labeled_finding()).unwrap();
    drop(store);

    let output = root.path().join("findings.json");
    super::super::export_workspace_findings_with_options(
        &workspace,
        &output,
        &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json)),
    )
    .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let basis = &document["findings"][0]["reviewDecisionBasis"];
    assert_eq!(basis["runId"], "run-a", "{document:#}");
    assert_eq!(basis["laterObservation"]["runId"], "run-b");
    assert!(basis["sourceChangedSinceDecision"].is_boolean());
}

fn finding_with(rule: &str) -> Finding {
    Finding::new_tool("semgrep", rule, "src/lib.rs", 3, None, Severity::High, rule)
}

/// The store lists equal-severity findings newest first, while export rows
/// order them by fingerprint. Inserting the smaller fingerprint first makes
/// the two orders disagree, which is when rows and findings must not be
/// paired by position.
#[test]
fn decision_basis_follows_its_finding_when_rows_are_reordered() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-a", root.path(), "running")
        .unwrap();
    let mut pair = [finding_with("pair.one"), finding_with("pair.two")];
    pair.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    let decided = store.insert_finding("run-a", &pair[0]).unwrap();
    store.insert_finding("run-a", &pair[1]).unwrap();
    confirm(&store, decided);
    assert_eq!(
        store.list_all_findings().unwrap()[0].fingerprint,
        pair[1].fingerprint,
        "fixture must list the undecided finding first"
    );
    drop(store);

    let output = root.path().join("findings.json");
    super::super::export_workspace_findings_with_options(
        &workspace,
        &output,
        &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json)),
    )
    .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    let rows = document["findings"].as_array().unwrap();
    assert_eq!(rows[0]["fingerprint"], pair[0].fingerprint, "{document:#}");
    assert_eq!(rows[0]["reviewDecisionBasis"]["runId"], "run-a");
    assert!(rows[1]["reviewDecisionBasis"].is_null(), "{document:#}");
}
