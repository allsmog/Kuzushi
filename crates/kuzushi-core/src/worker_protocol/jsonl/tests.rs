use super::*;
use serde_json::{json, Value};

#[test]
fn verified_length_rejects_a_replaced_path() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("events.jsonl");
    let displaced = temp.path().join("displaced.jsonl");
    fs::write(&path, b"{}\n").unwrap();
    let file = File::open(&path).unwrap();
    fs::rename(&path, displaced).unwrap();
    fs::write(&path, b"{}\n").unwrap();
    let limits = JsonlLimits::testing("test.log", 8, 2, 4, 8);

    assert_eq!(
        verified_jsonl_file_len(&file, &path, limits).unwrap_err(),
        KwpError::denied("test.log.identity")
    );
}

#[test]
fn exact_file_and_record_boundaries_succeed() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("events.jsonl");
    fs::write(&path, b"{}\n{}\n").unwrap();
    let limits = JsonlLimits::testing("test.log", 6, 2, 2, 4);

    let records = read_bounded_jsonl::<Value>(&path, limits, MissingFile::Error).unwrap();
    assert_eq!(records, vec![json!({}), json!({})]);
}

#[test]
fn each_limit_plus_one_has_a_stable_resource_label() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("events.jsonl");
    fs::write(&path, b"{}\n{}\n").unwrap();

    assert_limit(&path, [5, 2, 2, 4], "test.log.bytes");
    assert_limit(&path, [6, 1, 2, 4], "test.log.records");
    assert_limit(&path, [6, 2, 1, 4], "test.log.line.bytes");
    assert_limit(&path, [6, 2, 2, 3], "test.log.decoded.bytes");
}

fn assert_limit(path: &Path, values: [usize; 4], resource: &str) {
    let [file, records, line, decoded] = values;
    let limits = JsonlLimits::testing("test.log", file as u64, records, line, decoded as u64);
    assert_eq!(
        read_bounded_jsonl::<Value>(path, limits, MissingFile::Error).unwrap_err(),
        KwpError::quota(resource)
    );
}

#[test]
fn append_growth_checks_records_lines_and_total_bytes() {
    let limits = JsonlLimits::testing("test.log", 8, 2, 4, 8);
    assert!(ensure_jsonl_append_growth(3, 1, 4, limits).is_ok());
    assert_eq!(
        ensure_jsonl_append_growth(4, 1, 4, limits).unwrap_err(),
        KwpError::quota("test.log.bytes")
    );
    assert_eq!(
        ensure_jsonl_append_growth(0, 2, 1, limits).unwrap_err(),
        KwpError::quota("test.log.records")
    );
    assert_eq!(
        ensure_jsonl_append_growth(0, 0, 5, limits).unwrap_err(),
        KwpError::quota("test.log.line.bytes")
    );
}
