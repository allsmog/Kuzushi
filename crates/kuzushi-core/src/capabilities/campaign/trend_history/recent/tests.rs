use super::*;
use std::io::Write;

fn snapshot_line(index: usize) -> String {
    format!("{{\"tsMs\":{index},\"decidedFindings\":{index},\"confirmedFindings\":0,\"rejectedFalsePositives\":0,\"campaignSpendUsd\":0.0}}\n")
}

#[test]
fn recent_history_has_both_a_byte_and_row_bound() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("history.jsonl");
    let mut file = File::create(&path).unwrap();
    file.set_len(64 * 1024 * 1024).unwrap();
    file.seek(SeekFrom::End(0)).unwrap();
    writeln!(file).unwrap();
    for index in 0..100 {
        write!(file, "{}", snapshot_line(index)).unwrap();
    }
    drop(file);
    let (bytes, truncated) = read_history_tail(File::open(&path).unwrap()).unwrap();
    assert!(truncated);
    assert_eq!(bytes.len(), MAX_HISTORY_BYTES as usize);
    let history = load_recent_history(root.path(), &path, usize::MAX).unwrap();
    assert_eq!(history.len(), TREND_HISTORY_LIMIT);
    assert_eq!(history.first().unwrap().decided_findings, 10);
    assert_eq!(history.last().unwrap().decided_findings, 99);
}

#[test]
fn truncated_prefix_and_malformed_tail_cannot_become_snapshots() {
    let bytes = format!(
        "{}{}bad\n{}{{\"tsMs\":9",
        snapshot_line(1),
        snapshot_line(2),
        snapshot_line(3)
    );
    let history = parse_recent_snapshots(bytes.as_bytes(), true, 10);
    assert_eq!(
        history.iter().map(|row| row.ts_ms).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(parse_recent_snapshots(snapshot_line(1).as_bytes(), false, 0).is_empty());
    assert!(parse_recent_snapshots(b"no complete line", true, 10).is_empty());
}

#[test]
fn invalid_bytes_do_not_hide_other_complete_rows() {
    let mut bytes = snapshot_line(1).into_bytes();
    bytes.extend_from_slice(b"\xff\n");
    bytes.extend_from_slice(snapshot_line(2).as_bytes());
    let history = parse_recent_snapshots(&bytes, false, 10);
    assert_eq!(
        history.iter().map(|row| row.ts_ms).collect::<Vec<_>>(),
        vec![1, 2]
    );
}

#[cfg(unix)]
#[test]
fn recent_history_refuses_symlinked_paths_and_other_file_types() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let path = root.path().join("history.jsonl");
    let actual = outside.path().join("history.jsonl");
    std::fs::write(&actual, snapshot_line(1)).unwrap();
    std::os::unix::fs::symlink(&actual, &path).unwrap();
    assert!(load_recent_history(root.path(), &path, 10).is_err());
    let linked_dir = root.path().join("linked-history");
    std::os::unix::fs::symlink(outside.path(), &linked_dir).unwrap();
    assert!(load_recent_history(root.path(), &linked_dir.join("history.jsonl"), 10).is_err());
    assert!(load_recent_history(root.path(), root.path(), 10).is_err());
    assert!(load_recent_history(root.path(), &path, 0)
        .unwrap()
        .is_empty());
}
