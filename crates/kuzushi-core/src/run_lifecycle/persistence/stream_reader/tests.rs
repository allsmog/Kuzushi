use super::*;
use std::fs;
use std::io::Write;

#[test]
fn reader_enforces_record_and_item_limits_before_unbounded_growth() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("items.jsonl");
    fs::write(&path, b"one\ntwo\nthree\n").unwrap();
    let limits = StreamLimits {
        bytes: 32,
        record_bytes: 5,
        items: 2,
    };
    let mut reader = RunItemStreamReader::open_with_limits(&path, limits)
        .unwrap()
        .unwrap();
    assert!(reader.next_record().unwrap().is_some());
    assert!(reader.next_record().unwrap().is_some());
    assert!(reader
        .next_record()
        .unwrap_err()
        .to_string()
        .contains("item limit"));

    fs::write(&path, b"123456\n").unwrap();
    let mut reader = RunItemStreamReader::open_with_limits(&path, limits)
        .unwrap()
        .unwrap();
    assert!(reader
        .next_record()
        .unwrap_err()
        .to_string()
        .contains("record"));
}

#[test]
fn reader_detects_truncation_and_committed_prefix_changes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("items.jsonl");
    fs::write(&path, b"first\nsecond\n").unwrap();
    let mut reader = RunItemStreamReader::open(&path).unwrap().unwrap();
    reader.next_record().unwrap().unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .write_all(b"other")
        .unwrap();
    assert!(reader.verify_path_unchanged().is_err());

    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(0)
        .unwrap();
    assert!(reader.verify_path_unchanged().is_err());
}

#[test]
fn reader_verifies_the_entire_consumed_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("items.jsonl");
    fs::write(&path, b"first\nsecond\n").unwrap();
    let mut reader = RunItemStreamReader::open(&path).unwrap().unwrap();
    reader.next_record().unwrap().unwrap();
    reader.next_record().unwrap().unwrap();

    let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.write_all(b"other").unwrap();

    let error = reader.verify_path_unchanged().unwrap_err();
    assert!(error.to_string().contains("committed prefix changed"));
}

#[test]
fn checkpoint_restore_replays_consumed_records() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("items.jsonl");
    fs::write(&path, b"first\nsecond\n").unwrap();
    let mut reader = RunItemStreamReader::open(&path).unwrap().unwrap();
    let checkpoint = reader.checkpoint();
    assert_eq!(reader.next_record().unwrap().unwrap().bytes, b"first");

    reader.restore(checkpoint).unwrap();

    assert_eq!(reader.next_record().unwrap().unwrap().bytes, b"first");
    assert_eq!(reader.records_read(), 1);
}

#[cfg(unix)]
#[test]
fn rooted_reader_rejects_parent_replaced_after_path_validation() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let run_dir = temp.path().join(".kuzushi/v3/runs/run-1");
    let displaced = temp.path().join("displaced-run");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&run_dir).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(run_dir.join("items.jsonl"), b"inside\n").unwrap();
    fs::write(outside.join("items.jsonl"), b"outside\n").unwrap();
    let checked =
        crate::run_artifacts::checked_run_artifact_path(temp.path(), "run-1", "items.jsonl")
            .unwrap();

    fs::rename(&run_dir, &displaced).unwrap();
    symlink(&outside, &run_dir).unwrap();

    let error = match RunItemStreamReader::open_within(temp.path(), &checked) {
        Err(error) => error,
        Ok(_) => panic!("rooted reader followed a replaced parent"),
    };
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}
