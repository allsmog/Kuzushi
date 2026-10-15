use super::*;
use serde_json::json;

fn snapshot() -> Value {
    json!({"filesSample":["owned.rs"],"repositoryInventory":{"inspection":{
        "enumeration":"filesystem","entries":3,"max_entries":100000,
        "inspected_bytes":42,"max_inspected_bytes":536870912,"max_file_inspection_bytes":262144,
        "files":["owned.rs","notes.txt"],"omitted_paths":[],"truncated_files":["notes.txt"]}}})
}

#[test]
fn recorded_inspection_separates_enumeration_sample_and_content_limits() {
    let receipt = context_snapshot_inspection(&snapshot()).unwrap();
    assert_eq!(receipt.enumeration, ContextEnumeration::Filesystem);
    assert_eq!(
        (
            receipt.entries,
            receipt.enumerated_files,
            receipt.sampled_files
        ),
        (3, 2, 1)
    );
    assert_eq!(receipt.truncated_files, 1);
    assert!(!receipt.truncated);
    let mut value = snapshot();
    value["repositoryInventory"]["inspection"]["enumeration"] = json!("git-index");
    value["repositoryInventory"]["truncation"] = json!({"reason":"Owned entry cap"});
    let receipt = context_snapshot_inspection(&value).unwrap();
    assert_eq!(receipt.enumeration, ContextEnumeration::GitIndex);
    assert!(receipt.truncated);
}

#[test]
fn missing_or_malformed_extent_stays_unknown_instead_of_zero() {
    assert!(context_snapshot_inspection(&json!({})).is_none());
    for field in [
        "entries",
        "max_entries",
        "inspected_bytes",
        "max_inspected_bytes",
        "max_file_inspection_bytes",
    ] {
        let mut value = snapshot();
        value["repositoryInventory"]["inspection"][field] = json!("unknown");
        assert!(context_snapshot_inspection(&value).is_none());
    }
    let mut value = snapshot();
    value["repositoryInventory"]["inspection"]["enumeration"] = json!("\u{1b}[31mforged");
    assert!(context_snapshot_inspection(&value).is_none());
}

#[test]
fn interrupted_enumeration_keeps_the_partial_receipt_readable() {
    let mut value = snapshot();
    value["repositoryInventory"]["inspection"]["enumeration"] = json!("interrupted");
    value["repositoryInventory"]["truncation"] =
        json!({"reason":"canceled during path acquisition"});
    let receipt = context_snapshot_inspection(&value).unwrap();
    assert_eq!(receipt.enumeration, ContextEnumeration::Interrupted);
    assert!(receipt.truncated);
}
