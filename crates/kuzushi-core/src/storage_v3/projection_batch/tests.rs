use super::*;
use crate::event_log::{EventAppend, EventLog};
use serde_json::json;

fn snapshot() -> EventAppend {
    EventAppend {
        kind: EventKind::SnapshotIndexed,
        actor: "test".into(),
        payload: json!({"snapshotHash":"snapshot","treeHash":"tree","workspaceRootFingerprint":"owned"}),
    }
}

#[test]
fn failed_projection_rolls_back_the_entire_contiguous_group() {
    let root = tempfile::tempdir().unwrap();
    let log = EventLog::open(root.path()).unwrap();
    let events = log
        .append_batch(vec![
            snapshot(),
            EventAppend {
                kind: EventKind::FileIndexed,
                actor: "test".into(),
                payload: json!({}),
            },
        ])
        .unwrap();
    let db = ProjectionDb::open_in_memory().unwrap();
    assert!(db.apply_event_batch(&events).is_err());
    assert_eq!(db.meta().unwrap().applied_seq, 0);
    let count: i64 = db
        .conn
        .query_row("select count(*) from target_snapshots", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    db.apply_event(&events[0]).unwrap();
    assert_eq!(db.meta().unwrap().applied_seq, 1);
}

#[test]
fn projection_batch_refuses_a_gap_or_repeated_event() {
    let root = tempfile::tempdir().unwrap();
    let log = EventLog::open(root.path()).unwrap();
    let events = log.append_batch(vec![snapshot(), snapshot()]).unwrap();
    let db = ProjectionDb::open_in_memory().unwrap();
    assert!(db.apply_event_batch(&events[1..]).is_err());
    db.apply_event_batch(&events).unwrap();
    assert_eq!(db.meta().unwrap().applied_seq, 2);
    assert!(db.apply_event_batch(&events).is_err());
    assert_eq!(db.meta().unwrap().applied_seq, 2);
}
