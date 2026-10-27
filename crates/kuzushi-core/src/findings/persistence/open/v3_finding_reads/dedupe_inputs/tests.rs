use super::*;

fn seeded() -> (tempfile::TempDir, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    let store = FindingStore::open(root.path().join("findings.db")).unwrap();
    store
        .with_run_lifecycle("owned-input", root.path(), || {
            let findings = ["a", "b"].map(|rule| {
                Finding::new_tool(
                    "owned",
                    rule,
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled inert dedupe input λ界",
                )
            });
            store.insert_findings("owned-input", &findings)?;
            Ok(((), 2usize))
        })
        .unwrap();
    (root, store)
}

#[test]
fn read_limits_refuse_a_partial_pool_and_leave_the_ledger_usable() {
    let (_root, store) = seeded();
    let limits = DedupeLedgerLimits {
        max_observations: 1,
        ..Default::default()
    };
    let result = store.read_dedupe_ledger(limits, None);
    assert!(result.is_err(), "the oversized pool must not be returned");
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("maxLedgerObservations"));
    assert!(store.conn.is_autocommit());
    assert_eq!(store.list_all_findings().unwrap().len(), 2);
    assert_eq!(
        store
            .read_dedupe_ledger(Default::default(), None)
            .unwrap()
            .observations_read,
        2
    );
}

#[test]
fn raw_and_projected_utf8_share_one_byte_allowance() {
    let (_root, store) = seeded();
    let raw: usize = store
        .conn
        .query_row(
            "select sum(length(cast(finding_json as blob))) from finding_observations",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap() as usize;
    let characters: i64 = store
        .conn
        .query_row(
            "select sum(length(finding_json)) from finding_observations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        raw > characters as usize,
        "the fixture must contain multi-byte text"
    );
    for maximum in [raw - 1, raw] {
        let result = store.read_dedupe_ledger(
            DedupeLedgerLimits {
                max_bytes: maximum,
                ..Default::default()
            },
            None,
        );
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .root_cause()
            .to_string()
            .contains("maxLedgerBytes"));
        assert!(store.conn.is_autocommit());
    }
    let read = store.read_dedupe_ledger(Default::default(), None).unwrap();
    assert!(read.encoded_bytes_read > raw);
}

#[test]
fn cancellation_and_invalid_limits_do_not_leave_a_transaction_or_callback() {
    let (_root, store) = seeded();
    let cancellation = ScanCancellation::default();
    cancellation.cancel();
    let result = store.read_dedupe_ledger(Default::default(), Some(&cancellation));
    assert!(result
        .err()
        .unwrap()
        .root_cause()
        .to_string()
        .contains("cancelled"));
    let result = store.read_dedupe_ledger(
        DedupeLedgerLimits {
            read_ms: 0,
            ..Default::default()
        },
        None,
    );
    assert!(result
        .err()
        .unwrap()
        .root_cause()
        .to_string()
        .contains("maxLedgerReadMs"));
    assert!(store.conn.is_autocommit());
    assert_eq!(
        store
            .read_dedupe_ledger(Default::default(), None)
            .unwrap()
            .findings
            .len(),
        2
    );
}

#[test]
fn dedupe_matches_current_sources_identity_and_suppression_without_proof_hydration() {
    let (_root, store) = seeded();
    store
        .conn
        .execute("update stable_findings set current_status='suppressed'", [])
        .unwrap();
    let expected = store.list_all_findings().unwrap();
    let actual = store
        .read_dedupe_ledger(Default::default(), None)
        .unwrap()
        .findings;
    assert_eq!(actual.len(), expected.len());
    for (left, right) in actual.iter().zip(&expected) {
        assert_eq!(
            serde_json::to_value(left).unwrap(),
            serde_json::to_value(right).unwrap()
        );
        assert!(left.suppressed);
    }
}

#[test]
fn indexed_rekey_exclusion_does_not_rewrite_or_delete_observations() {
    let (_root, store) = seeded();
    let before = store.list_all_findings().unwrap();
    let key = crate::findings::finding_observation_identity(&before[0]);
    store.conn.execute("insert into rekey_edges(old_fp,new_fp,event_hash,method,confidence) values (?1,'other','owned','test',1)", [key]).unwrap();
    let read = store.read_dedupe_ledger(Default::default(), None).unwrap();
    assert_eq!(read.observations_read, 2);
    assert_eq!(read.findings.len(), 1);
    assert_eq!(read.findings[0].fingerprint, before[1].fingerprint);
    assert_eq!(store.list_all_findings().unwrap().len(), 2);
}
