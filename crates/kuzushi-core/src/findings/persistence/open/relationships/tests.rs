use super::*;
use crate::findings::{Finding, Severity};

mod batch;

fn seeded() -> (tempfile::TempDir, FindingStore, Vec<i64>) {
    let root = tempfile::tempdir().unwrap();
    let store = FindingStore::open(root.path().join("findings.db")).unwrap();
    for (run, rule) in [("a", "first"), ("b", "second")] {
        store
            .with_run_lifecycle(run, root.path(), || {
                let finding = Finding::new_tool(
                    "owned-fixture",
                    rule,
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled relationship observation",
                );
                store.insert_finding(run, &finding)?;
                Ok(((), 1))
            })
            .unwrap();
    }
    let ids = store
        .list_all_findings()
        .unwrap()
        .iter()
        .map(|row| row.id.unwrap())
        .collect();
    (root, store, ids)
}

#[test]
fn relationship_review_and_undo_preserve_observations_identities_and_verdicts() {
    let (_root, store, ids) = seeded();
    let before = store.list_all_findings().unwrap();
    let proposal = store
        .propose_finding_relationship(
            ids[0],
            ids[1],
            FindingRelationshipKind::Duplicate,
            "Labeled same source",
            Some(0.95),
        )
        .unwrap();
    let accepted = store
        .review_finding_relationship(
            &proposal.id,
            FindingRelationshipState::Accepted,
            "Reviewed both sources",
            1,
        )
        .unwrap();
    let removed = store
        .review_finding_relationship(
            &proposal.id,
            FindingRelationshipState::Removed,
            "Separate causes",
            2,
        )
        .unwrap();
    assert_eq!(removed.revision, 3);
    assert_eq!(
        store
            .finding_relationships(Some(ids[1]), 20, 0)
            .unwrap()
            .rows,
        vec![removed]
    );
    assert_eq!(store.list_all_findings().unwrap(), before);
    assert!(store
        .rekey_targets_for(&accepted.from.stable_key)
        .unwrap()
        .is_empty());
    assert!(store
        .latest_review_decisions_for_findings(&before, true)
        .unwrap()
        .is_empty());
    let again = store
        .propose_finding_relationship(
            ids[0],
            ids[1],
            FindingRelationshipKind::Duplicate,
            "Repeated model suggestion",
            Some(0.9),
        )
        .unwrap();
    assert_eq!(again.revision, 3);
}

#[test]
fn stale_reviews_are_rejected_and_new_recorded_runs_do_not_rebind_a_relationship() {
    let (_root, store, ids) = seeded();
    let proposal = store
        .propose_finding_relationship(
            ids[0],
            ids[1],
            FindingRelationshipKind::RelatedVariant,
            "Related patterns",
            None,
        )
        .unwrap();
    store
        .review_finding_relationship(
            &proposal.id,
            FindingRelationshipState::Rejected,
            "Different contexts",
            1,
        )
        .unwrap();
    assert!(store
        .review_finding_relationship(
            &proposal.id,
            FindingRelationshipState::Accepted,
            "Stale editor",
            1
        )
        .is_err());
    assert!(store
        .propose_finding_relationship(
            ids[0],
            ids[0],
            FindingRelationshipKind::Duplicate,
            "Self link",
            None
        )
        .is_err());
    let page = store.finding_relationships(None, 1, 0).unwrap();
    assert_eq!(page.rows.len(), 1);
    assert!(!page.has_more);
    assert!(store.finding_relationships(None, 0, 0).is_err());
}

#[test]
fn model_proposals_refuse_candidates_changed_since_the_model_read_them() {
    let (root, store, _) = seeded();
    let before = store.list_all_findings().unwrap();
    store
        .with_run_lifecycle("later", root.path(), || {
            store.insert_finding("later", &before[0])?;
            Ok(((), 1))
        })
        .unwrap();
    let error = store
        .propose_recorded_finding_relationship(
            &before[0],
            &before[1],
            FindingRelationshipKind::Duplicate,
            "Stale model proposal",
            Some(0.9),
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("changed during relationship review"));
    assert!(store
        .finding_relationships(None, 50, 0)
        .unwrap()
        .rows
        .is_empty());
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}
