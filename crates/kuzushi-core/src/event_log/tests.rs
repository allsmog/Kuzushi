use super::*;
use serde_json::json;

#[test]
fn appends_and_verifies_hash_chain() {
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();

    let first = log
        .append(
            EventKind::RunStarted,
            "test",
            Some("run-1".to_string()),
            None,
            json!({}),
        )
        .unwrap();
    let second = log
        .append(
            EventKind::TriageDecided,
            "reviewer",
            Some("run-1".to_string()),
            None,
            json!({"stableFp":"fp3_a"}),
        )
        .unwrap();

    assert_eq!(first.seq, 1);
    assert_eq!(second.seq, 2);
    assert_eq!(second.prev_event_hash, Some(first.event_hash));
    log.verify_chain().unwrap();
}

#[test]
fn writes_checkpoint_file_for_event_sequence() {
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = log
        .append(
            EventKind::ProjectionCheckpointed,
            "writer",
            None,
            None,
            json!({"appliedSeqBeforeCheckpoint": 7}),
        )
        .unwrap();

    let path = log.write_checkpoint(&event).unwrap();

    assert_eq!(
        path,
        tmp.path()
            .join("checkpoints")
            .join("checkpoint-000000000001.json")
    );
    let checkpoint: EventEnvelope =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(checkpoint.event_hash, event.event_hash);
    assert_eq!(checkpoint.event_kind, EventKind::ProjectionCheckpointed);
}

#[test]
fn reads_hash_chain_across_rolled_segments() {
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let first = log
        .append(
            EventKind::RunStarted,
            "test",
            Some("run-1".to_string()),
            None,
            json!({}),
        )
        .unwrap();
    let next_segment = log.roll_segment().unwrap();
    assert_eq!(next_segment, tmp.path().join("events-000001.jsonl"));

    let second = log
        .append(
            EventKind::RunCompleted,
            "test",
            Some("run-1".to_string()),
            None,
            json!({"status": "completed"}),
        )
        .unwrap();

    assert_eq!(second.seq, 2);
    assert_eq!(second.prev_event_hash, Some(first.event_hash));
    log.verify_chain().unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_kind, EventKind::RunStarted);
    assert_eq!(events[1].event_kind, EventKind::RunCompleted);
}
