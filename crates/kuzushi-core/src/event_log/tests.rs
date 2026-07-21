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

#[test]
fn verification_rejects_non_contiguous_sequence_numbers() {
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    log.append(
        EventKind::RunStarted,
        "test",
        Some("run-1".to_string()),
        None,
        json!({}),
    )
    .unwrap();
    let path = tmp.path().join("events-000000.jsonl");
    let mut value: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
    value["seq"] = json!(2);
    std::fs::write(
        &path,
        format!("{}\n", serde_json::to_string(&value).unwrap()),
    )
    .unwrap();

    let reopened = EventLog::open(tmp.path()).unwrap();
    let error = reopened.verify_chain().unwrap_err();

    assert!(error.to_string().contains("expected 1, found 2"));
}

#[cfg(unix)]
#[test]
fn checkpoint_write_rejects_symlink_directory() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    let event = log
        .append(
            EventKind::ProjectionCheckpointed,
            "writer",
            None,
            None,
            json!({}),
        )
        .unwrap();
    symlink(outside.path(), tmp.path().join("checkpoints")).unwrap();

    assert!(log.write_checkpoint(&event).is_err());
    assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn segment_append_and_read_reject_symlink_without_touching_outside_file() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    symlink(outside.path(), tmp.path().join("events-000000.jsonl")).unwrap();
    let log = EventLog::open(tmp.path()).unwrap();

    assert!(log
        .append(EventKind::RunStarted, "writer", None, None, json!({}))
        .is_err());
    assert!(log.read_all().is_err());
    assert!(std::fs::read(outside.path()).unwrap().is_empty());
}

#[test]
fn event_log_rejects_oversized_segments_before_reading_them() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("events-000000.jsonl");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(MAX_EVENT_LOG_SEGMENT_BYTES + 1)
        .unwrap();
    let log = EventLog::open(tmp.path()).unwrap();

    let error = log.read_all().unwrap_err();

    assert!(error.to_string().contains("segment exceeds"));
}

#[test]
fn event_log_rejects_an_oversized_single_line() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("events-000000.jsonl");
    std::fs::write(&path, "x".repeat(MAX_EVENT_LOG_LINE_BYTES + 1)).unwrap();
    let log = EventLog::open(tmp.path()).unwrap();

    let error = log.read_all().unwrap_err();

    assert!(error.to_string().contains("line 1"));
}

#[test]
fn event_log_enforces_the_aggregate_event_limit_while_parsing() {
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    log.append(EventKind::RunStarted, "writer", None, None, json!({}))
        .unwrap();
    let path = tmp.path().join("events-000000.jsonl");
    let body = std::fs::read_to_string(&path).unwrap();

    let error = parse_segment_body(&path, &body, 0).unwrap_err();

    assert!(error.to_string().contains("aggregate limit"));
}

#[test]
fn torn_tail_from_a_killed_writer_is_tolerated_and_healed_on_next_append() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("events-000000.jsonl");
    {
        let log = EventLog::open(tmp.path()).unwrap();
        log.append(EventKind::RunStarted, "writer", Some("r1".into()), None, json!({}))
            .unwrap();
    }
    // Simulate SIGKILL mid-append: a partial line with no trailing newline,
    // cut inside a multi-byte UTF-8 character for good measure.
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(br#"{"seq":2,"actor":"caf"#);
    bytes.extend_from_slice(&[0xC3]); // first byte of a two-byte char
    std::fs::write(&path, &bytes).unwrap();

    // Reopen: the store must not brick — the durable prefix reads and the
    // chain verifies.
    let log = EventLog::open(tmp.path()).unwrap();
    let events = log.read_all().unwrap();
    assert_eq!(events.len(), 1);
    log.verify_chain().unwrap();

    // The next append truncates the torn bytes and continues the chain.
    let second = log
        .append(EventKind::RunCompleted, "writer", Some("r1".into()), None, json!({}))
        .unwrap();
    assert_eq!(second.seq, 2);
    assert_eq!(second.prev_event_hash, Some(events[0].event_hash.clone()));
    let healed = std::fs::read(&path).unwrap();
    assert!(healed.ends_with(b"\n"), "healed segment must end at a full line");
    let reopened = EventLog::open(tmp.path()).unwrap();
    assert_eq!(reopened.read_all().unwrap().len(), 2);
    reopened.verify_chain().unwrap();
}

#[test]
fn torn_tail_outside_the_active_segment_stays_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    log.append(EventKind::RunStarted, "writer", None, None, json!({}))
        .unwrap();
    let rolled = log.roll_segment().unwrap();
    std::fs::write(&rolled, "{\"seq\":2}\n").unwrap_or_default();
    // Corrupt the FIRST (non-active) segment with a newline-less tail.
    let first = tmp.path().join("events-000000.jsonl");
    let mut bytes = std::fs::read(&first).unwrap();
    bytes.extend_from_slice(b"{\"torn");
    std::fs::write(&first, &bytes).unwrap();

    let error = log.read_all().unwrap_err().to_string();

    assert!(error.contains("torn"), "{error}");
}

#[test]
fn garbage_complete_line_is_still_hard_corruption() {
    let tmp = tempfile::tempdir().unwrap();
    let log = EventLog::open(tmp.path()).unwrap();
    log.append(EventKind::RunStarted, "writer", None, None, json!({}))
        .unwrap();
    let path = tmp.path().join("events-000000.jsonl");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(b"not-json-but-newline-terminated\n");
    std::fs::write(&path, &bytes).unwrap();

    let error = log.read_all().unwrap_err().to_string();

    assert!(error.contains("Invalid event log line"), "{error}");
}
