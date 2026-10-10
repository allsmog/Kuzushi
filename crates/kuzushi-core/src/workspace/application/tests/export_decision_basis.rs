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
    let basis = basis(
        decided.clone(),
        Some(decided),
        WorkspaceReviewSourceComparison::NotReobserved,
    );
    assert_eq!(basis.run_id, "run-a");
    assert!(basis.later_observation.is_none());
    assert!(!basis.source_changed_since_decision);
}

#[test]
fn later_observation_on_changed_source_is_disclosed() {
    let basis = basis(
        observed(4, "run-a", "snap-1"),
        Some(observed(9, "run-b", "snap-2")),
        WorkspaceReviewSourceComparison::DifferentCitedSource,
    );
    assert_eq!(basis.later_observation.as_ref().unwrap().run_id, "run-b");
    assert!(basis.source_changed_since_decision);
}

#[test]
fn later_observation_on_identical_source_is_not_a_source_change() {
    let basis = basis(
        observed(4, "run-a", "snap-1"),
        Some(observed(9, "run-b", "snap-1")),
        WorkspaceReviewSourceComparison::SameCitedSource,
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

fn export_document(workspace: &WorkspaceTarget) -> serde_json::Value {
    let output = workspace.root().join("decision-basis.json");
    super::super::export_workspace_findings_with_options(
        workspace,
        &output,
        &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::Json)),
    )
    .unwrap();
    serde_json::from_slice(&fs::read(output).unwrap()).unwrap()
}

#[test]
fn decision_basis_keeps_the_effective_human_verdict_after_a_later_import() {
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
    let later_id = store.insert_finding("run-b", &labeled_finding()).unwrap();
    store
        .append_user_review_decision(
            later_id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::NeedsReview,
                author: TriageAuthor::Imported,
                confidence: 0.5,
                rationale: "Labeled imported review, after the operator verdict".into(),
                dismiss_reason: None,
                actor: Some("fixture-import".into()),
            },
        )
        .unwrap();
    drop(store);

    let document = export_document(&workspace);
    let finding = &document["findings"][0];
    assert_eq!(finding["reviewDecision"], "confirmed", "{document:#}");
    assert_eq!(finding["reviewDecisionAuthor"], "human", "{document:#}");
    assert_eq!(
        finding["reviewDecisionBasis"]["runId"], "run-a",
        "{document:#}"
    );
}

#[test]
fn later_observation_of_identical_cited_source_is_not_a_source_change() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    fs::write(
        root.path().join("src/lib.rs"),
        "// Labeled source fixture, never executed.\npub fn record() -> u8 { 1 }\n",
    )
    .unwrap();
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

    let document = export_document(&workspace);
    let basis = &document["findings"][0]["reviewDecisionBasis"];
    assert_eq!(basis["runId"], "run-a", "{document:#}");
    assert_eq!(basis["laterObservation"]["runId"], "run-b", "{document:#}");
    assert_eq!(basis["sourceChangedSinceDecision"], false, "{document:#}");
    assert_eq!(
        basis["sourceComparison"], "same_cited_source",
        "{document:#}"
    );
}

#[test]
fn missing_captured_source_stays_unknown_when_observation_ids_differ() {
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
    let document = export_document(&workspace);
    let basis = &document["findings"][0]["reviewDecisionBasis"];
    assert_eq!(basis["sourceComparison"], "unknown", "{document:#}");
    assert_eq!(basis["sourceChangedSinceDecision"], false, "{document:#}");
    let bundle = root.path().join("bundle");
    super::super::export_workspace_findings_with_options(
        &workspace,
        &bundle,
        &WorkspaceExportOptions::new(Some(WorkspaceExportFormat::MarkdownBundle)),
    )
    .unwrap();
    let alias = document["findings"][0]["alias"].as_str().unwrap();
    let markdown = fs::read_to_string(bundle.join("findings").join(format!("{alias}.md"))).unwrap();
    assert!(markdown.contains("change status unknown"), "{markdown}");
    assert!(!markdown.contains("same source"), "{markdown}");
}

#[test]
fn changed_cited_file_is_disclosed_and_a_bounded_reader_keeps_the_older_view() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("src")).unwrap();
    let source = root.path().join("src/lib.rs");
    fs::write(
        &source,
        "// Labeled source fixture, never executed.\npub fn record() -> u8 { 1 }\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-a", root.path(), "running")
        .unwrap();
    let finding = labeled_finding();
    let id = store.insert_finding("run-a", &finding).unwrap();
    confirm(&store, id);
    let decision = store.list_review_decisions(id).unwrap().pop().unwrap();
    let watermark = decision.provenance.unwrap().read_watermark.unwrap();
    fs::write(
        &source,
        "// Labeled source fixture, never executed.\npub fn record() -> u8 { 2 }\n",
    )
    .unwrap();
    store
        .record_run_started("run-b", root.path(), "running")
        .unwrap();
    store.insert_finding("run-b", &finding).unwrap();
    let stable_fp = crate::findings::finding_stable_fp(
        &store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap(),
    );
    drop(store);
    let current = read_finding_review_source(&workspace, &stable_fp, watermark, None)
        .unwrap()
        .unwrap();
    assert!(current.source_changed_since_decision);
    assert_eq!(
        current.source_comparison,
        WorkspaceReviewSourceComparison::DifferentCitedSource
    );
    let older = read_finding_review_source(&workspace, &stable_fp, watermark, Some(watermark))
        .unwrap()
        .unwrap();
    assert_eq!(older.run_id, "run-a");
    assert!(older.later_observation.is_none());
    assert_eq!(
        older.source_comparison,
        WorkspaceReviewSourceComparison::NotReobserved
    );
}
