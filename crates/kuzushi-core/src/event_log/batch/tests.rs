use super::*;
use serde_json::json;

fn record(number: usize) -> EventAppend {
    EventAppend {
        kind: EventKind::FileIndexed,
        actor: "owned-index-test".into(),
        payload: json!({"number":number}),
    }
}

#[test]
fn source_batch_retains_each_envelope_and_continues_the_hash_chain() {
    let root = tempfile::tempdir().unwrap();
    let log = EventLog::open(root.path()).unwrap();
    let first = log
        .append(EventKind::SnapshotIndexed, "test", None, None, json!({}))
        .unwrap();
    log.roll_segment().unwrap();
    let batch = log.append_batch((0..128).map(record).collect()).unwrap();
    assert_eq!(batch.len(), 128);
    assert_eq!(batch[0].seq, 2);
    assert_eq!(batch[0].prev_event_hash, Some(first.event_hash));
    assert_eq!(batch[127].seq, 129);
    let next = log
        .append(EventKind::DiagnosticRecorded, "test", None, None, json!({}))
        .unwrap();
    assert_eq!(next.seq, 130);
    EventLog::open(root.path()).unwrap().verify_chain().unwrap();
    assert_eq!(log.read_all().unwrap().len(), 130);
}

#[test]
fn count_and_line_limits_fail_before_any_batch_append() {
    let root = tempfile::tempdir().unwrap();
    let log = EventLog::open(root.path()).unwrap();
    assert!(log.append_batch((0..129).map(record).collect()).is_err());
    let mut oversized = record(0);
    oversized.payload = json!({"large":"x".repeat(MAX_EVENT_LOG_LINE_BYTES)});
    assert!(log.append_batch(vec![record(1), oversized]).is_err());
    assert_eq!(log.head_seq().unwrap(), 0);
    assert!(log.read_all().unwrap().is_empty());
    assert!(log.append_batch(Vec::new()).unwrap().is_empty());
}

#[test]
fn failed_namespace_sync_reloads_the_batch_head_before_retry() {
    let root = tempfile::tempdir().unwrap();
    let log = EventLog::open(root.path()).unwrap();
    assert!(log
        .append_batch_with_sync(vec![record(0), record(1)], |_| anyhow::bail!(
            "test sync failure"
        ))
        .is_err());
    let retried = log
        .append(EventKind::DiagnosticRecorded, "test", None, None, json!({}))
        .unwrap();
    assert_eq!(retried.seq, 3);
    log.verify_chain().unwrap();
}
