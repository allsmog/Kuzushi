use super::*;

fn row(run_id: &str) -> FoldedFinding {
    parse_and_fold(
        &serde_json::json!({
            "event":"recorded", "finding_id":"owned", "run_id":run_id
        })
        .to_string(),
    )
    .0
    .remove(0)
}

fn ledger(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("findings.jsonl"),
        serde_json::json!({
            "finding_id":"owned", "crash_output":"Owned inert stored text"
        })
        .to_string(),
    )
    .unwrap();
}

#[test]
fn only_contained_regular_ledgers_supply_text() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    ledger(&data.join("runs/owned"));
    ledger(&root.path().join("excluded"));
    assert_eq!(
        run_crash_output(&data, &row("owned")).as_deref(),
        Some("Owned inert stored text")
    );
    assert!(run_crash_output(&data, &row("../../excluded")).is_none());
    assert!(
        run_crash_output(&data, &row(root.path().join("excluded").to_str().unwrap())).is_none()
    );
}

#[cfg(unix)]
#[test]
fn linked_ledger_ancestor_cannot_supply_text() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let excluded = root.path().join("excluded");
    ledger(&excluded);
    std::fs::create_dir_all(data.join("runs")).unwrap();
    std::os::unix::fs::symlink(&excluded, data.join("runs/linked")).unwrap();
    assert!(run_crash_output(&data, &row("linked")).is_none());
}
