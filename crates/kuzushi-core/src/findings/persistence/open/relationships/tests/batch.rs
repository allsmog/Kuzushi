use super::*;

fn fixture() -> (tempfile::TempDir, FindingStore, Vec<FindingRelationship>) {
    let (root, store, mut ids) = seeded();
    store
        .record_run_started("third", root.path(), "completed")
        .unwrap();
    ids.push(
        store
            .insert_finding(
                "third",
                &Finding::new_tool(
                    "owned-fixture",
                    "third",
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled third observation",
                ),
            )
            .unwrap(),
    );
    let records = [ids[1], ids[2]]
        .into_iter()
        .map(|id| {
            store
                .propose_finding_relationship(
                    ids[0],
                    id,
                    FindingRelationshipKind::Duplicate,
                    "Labeled same greeting",
                    None,
                )
                .unwrap()
        })
        .collect();
    (root, store, records)
}

#[test]
fn batch_is_one_replayable_event_and_single_undo_still_works() {
    let (root, store, records) = fixture();
    let before = store.list_all_findings().unwrap();
    let watermark = store.projection_meta().unwrap().applied_seq;
    let accepted = store
        .review_finding_relationship_batch(
            &records,
            FindingRelationshipState::Accepted,
            "Reviewed both pairs",
        )
        .unwrap();
    assert_eq!(store.projection_meta().unwrap().applied_seq, watermark + 1);
    assert_eq!(accepted.len(), 2);
    for row in &accepted {
        assert_eq!(
            store.finding_relationship(&row.id).unwrap(),
            Some(row.clone())
        );
    }
    let (log, db) = store.required_v3_storage_paths("test replay").unwrap();
    StorageWriterActor::commit_blocking(
        log,
        db,
        WriterCommand::Control(crate::storage_v3::writer_actor::ControlCommand::RebuildProjection),
    )
    .unwrap();
    let reopened = FindingStore::open(root.path().join("findings.db")).unwrap();
    assert_eq!(
        reopened
            .finding_relationships(None, 50, 0)
            .unwrap()
            .rows
            .len(),
        2
    );
    reopened
        .review_finding_relationship(
            &accepted[0].id,
            FindingRelationshipState::Removed,
            "Keep one pair separate",
            2,
        )
        .unwrap();
    assert_eq!(
        reopened
            .finding_relationship(&accepted[0].id)
            .unwrap()
            .unwrap()
            .state,
        FindingRelationshipState::Removed
    );
    assert_eq!(
        reopened
            .finding_relationship(&accepted[1].id)
            .unwrap()
            .unwrap(),
        accepted[1]
    );
    assert_eq!(reopened.list_all_findings().unwrap(), before);
    assert!(reopened.list_all_review_decisions().unwrap().is_empty());
}

#[test]
fn one_stale_revision_refuses_the_whole_selection_before_any_event() {
    let (_root, store, records) = fixture();
    store
        .review_finding_relationship(
            &records[1].id,
            FindingRelationshipState::Rejected,
            "Already reviewed",
            1,
        )
        .unwrap();
    let before = store.projection_meta().unwrap();
    assert!(store
        .review_finding_relationship_batch(
            &records,
            FindingRelationshipState::Accepted,
            "Stale batch"
        )
        .is_err());
    assert_eq!(store.projection_meta().unwrap(), before);
    assert_eq!(
        store.finding_relationship(&records[0].id).unwrap(),
        Some(records[0].clone())
    );
}

#[test]
fn source_drift_refuses_acceptance_but_historical_unlink_stays_available() {
    let (root, store, records) = fixture();
    let accepted = store
        .review_finding_relationship_batch(
            &records,
            FindingRelationshipState::Accepted,
            "Reviewed exact source",
        )
        .unwrap();
    let finding = store
        .get_finding_by_reference(&format!("generation:{}", records[1].to.finding_id))
        .unwrap()
        .unwrap();
    store
        .record_run_started("changed", root.path(), "completed")
        .unwrap();
    store.insert_finding("changed", &finding).unwrap();
    let before = store.projection_meta().unwrap();
    assert!(store
        .review_finding_relationship_batch(
            &accepted,
            FindingRelationshipState::Accepted,
            "Different source"
        )
        .is_err());
    assert_eq!(store.projection_meta().unwrap(), before);
    let removed = store
        .review_finding_relationship_batch(
            &accepted,
            FindingRelationshipState::Removed,
            "Undo historical grouping",
        )
        .unwrap();
    assert!(removed
        .iter()
        .all(|row| row.state == FindingRelationshipState::Removed));
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}

#[test]
fn invalid_selection_reason_and_authority_create_no_events() {
    let (_root, store, records) = fixture();
    let before = store.projection_meta().unwrap();
    for selection in [
        Vec::new(),
        vec![records[0].clone(), records[0].clone()],
        vec![records[0].clone(); 51],
    ] {
        assert!(store
            .review_finding_relationship_batch(
                &selection,
                FindingRelationshipState::Accepted,
                "Reviewed"
            )
            .is_err());
    }
    assert!(store
        .review_finding_relationship_batch(&records, FindingRelationshipState::Accepted, " ")
        .is_err());
    assert!(store
        .review_finding_relationship_batch(
            &records,
            FindingRelationshipState::Proposed,
            "Operator proposal"
        )
        .is_err());
    let mut altered = records.clone();
    altered[1].confidence = Some(1.0);
    assert!(store
        .review_finding_relationship_batch(
            &altered,
            FindingRelationshipState::Accepted,
            "Altered confidence snapshot"
        )
        .is_err());
    assert_eq!(store.projection_meta().unwrap(), before);
}

#[test]
fn concurrent_reviews_have_one_winner_and_never_commit_a_prefix() {
    let (root, store, records) = fixture();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = (0..2)
        .map(|_| {
            let path = root.path().join("findings.db");
            let records = records.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = FindingStore::open(path).unwrap();
                barrier.wait();
                store
                    .review_finding_relationship_batch(
                        &records,
                        FindingRelationshipState::Accepted,
                        "Reviewed concurrent selection",
                    )
                    .is_ok()
            })
        })
        .collect::<Vec<_>>();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| **result).count(), 1);
    assert!(store
        .finding_relationships(None, 50, 0)
        .unwrap()
        .rows
        .iter()
        .all(|row| row.revision == 2));
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}
