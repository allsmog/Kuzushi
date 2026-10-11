use super::candidates::{dedupe_candidates, stable_key};
use super::link::link_groups;
use super::{fingerprint_index, DuplicateGroup};
use crate::findings::{
    Finding, FindingStore, ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor,
};

fn seeded_store() -> (tempfile::TempDir, FindingStore) {
    let tmp = tempfile::tempdir().unwrap();
    let store = FindingStore::open(tmp.path().join("findings.db")).unwrap();
    for (run, tool, rule, line, title) in [
        (
            "run-a",
            "semgrep",
            "py.traversal",
            20,
            "Path traversal in download",
        ),
        (
            "run-b",
            "agentic-sast",
            "path-traversal-download",
            22,
            "Unvalidated path join lets clients escape the files dir",
        ),
    ] {
        store
            .with_run_lifecycle(run, tmp.path(), || {
                let mut finding = Finding::new_tool(
                    tool,
                    rule,
                    "webapp/files.py",
                    line,
                    None,
                    Severity::High,
                    title,
                );
                finding.title = title.to_string();
                store.insert_finding(run, &finding)?;
                Ok(((), 1usize))
            })
            .unwrap();
    }
    (tmp, store)
}

fn one_group(candidates: &[Finding]) -> Vec<DuplicateGroup> {
    vec![DuplicateGroup {
        canonical_fingerprint: candidates[0].fingerprint.clone(),
        duplicate_fingerprints: vec![candidates[1].fingerprint.clone()],
        root_cause_summary: "same unvalidated join in download handler".to_string(),
        confidence: 0.92,
    }]
}

#[test]
fn linking_is_idempotent_and_settles_the_duplicate() {
    let (_tmp, store) = seeded_store();
    let candidates = dedupe_candidates(&store, 200).unwrap();
    assert_eq!(
        candidates.len(),
        2,
        "cross-run same-file rows are candidates"
    );
    let groups = one_group(&candidates);
    let by_fp = fingerprint_index(&candidates);

    let first = link_groups(&store, "run-dedupe", &groups, &by_fp, false).unwrap();
    assert_eq!(first.linked, 1);
    assert!(first.verdicts_recorded >= 1);
    let duplicate_key = stable_key(&candidates[1]);
    let targets = store.rekey_targets_for(&duplicate_key).unwrap();
    assert_eq!(
        targets,
        vec![store
            .resolve_rekey_target(&stable_key(&candidates[0]))
            .unwrap()]
    );

    // Second run: the edge exists, so nothing is re-emitted.
    let second = link_groups(&store, "run-dedupe-2", &groups, &by_fp, false).unwrap();
    assert_eq!(second.linked, 0);
    assert_eq!(second.already_linked, 1);

    // The settled duplicate drops out of the next candidate pool entirely,
    // which also removes the lone survivor's bucket (needs >= 2 origins).
    let after = dedupe_candidates(&store, 200).unwrap();
    assert!(after.is_empty(), "expected no candidates, got {after:?}");
}

#[test]
fn model_dedupe_attaches_the_duplicate_fingerprint_to_the_canonical_identity() {
    let (_tmp, store) = seeded_store();
    let candidates = dedupe_candidates(&store, 200).unwrap();
    let by_fp = fingerprint_index(&candidates);
    link_groups(&store, "run-dedupe", &one_group(&candidates), &by_fp, false).unwrap();

    let canonical_identity = candidates[0].identity_id.clone().unwrap();
    let basis: String = store
        .conn
        .query_row(
            "select match_basis from finding_identity_fingerprints
              where identity_id = ?1 and fingerprint = ?2",
            rusqlite::params![canonical_identity, candidates[1].fingerprint],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(basis, "model_dedupe");
}

#[test]
fn dry_run_writes_nothing_and_human_verdicts_win() {
    let (_tmp, store) = seeded_store();
    let candidates = dedupe_candidates(&store, 200).unwrap();
    let groups = one_group(&candidates);
    let by_fp = fingerprint_index(&candidates);

    let dry = link_groups(&store, "run-dedupe", &groups, &by_fp, true).unwrap();
    assert_eq!(dry.linked, 1, "dry run reports what WOULD link");
    assert!(store
        .rekey_targets_for(&stable_key(&candidates[1]))
        .unwrap()
        .is_empty());

    let decision = ReviewDecision {
        verdict: ReviewDecisionVerdict::Confirmed,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: "verified live".to_string(),
        dismiss_reason: None,
        actor: None,
    };
    store
        .append_user_review_decision(candidates[1].id.unwrap(), &decision)
        .unwrap();
    let real = link_groups(&store, "run-dedupe", &groups, &by_fp, false).unwrap();
    assert_eq!(real.skipped_human, 1);
    assert_eq!(real.linked, 0);
    assert!(store
        .rekey_targets_for(&stable_key(&candidates[1]))
        .unwrap()
        .is_empty());
}

#[test]
fn default_dedupe_records_reversible_proposals_without_rekeys_or_false_positive_verdicts() {
    let (_root, store) = seeded_store();
    let candidates = dedupe_candidates(&store, 200).unwrap();
    let config = crate::V2Config::default();
    let ctx = crate::ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let before = store.list_all_findings().unwrap();
    let options = super::DedupeOptions::from_input(&serde_json::json!({})).unwrap();
    let report = super::record_dedupe_groups(
        &store,
        &ctx,
        &one_group(&candidates),
        &fingerprint_index(&candidates),
        &options,
    )
    .unwrap();
    assert_eq!(report.proposed, 1);
    assert_eq!(report.verdicts_recorded, 0);
    assert_eq!(report.linked, 0);
    assert_eq!(store.list_all_findings().unwrap(), before);
    assert!(store
        .latest_review_decisions_for_findings(&before, true)
        .unwrap()
        .is_empty());
    assert!(store
        .rekey_targets_for(&stable_key(&candidates[1]))
        .unwrap()
        .is_empty());
    assert_eq!(
        store.finding_relationships(None, 20, 0).unwrap().rows[0].state,
        crate::findings::FindingRelationshipState::Proposed
    );
}
