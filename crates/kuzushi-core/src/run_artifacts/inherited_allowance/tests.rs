use super::*;
use serde_json::json;

fn work() -> AllowanceWork {
    AllowanceWork {
        investigation_id: "owned-study".into(),
        revision: 1,
        run_id: "owned-parent".into(),
        work_id: "review".into(),
        model: "selected:model".into(),
        work: InvestigationWork::Review,
    }
}

#[test]
fn retention_is_idempotent_and_preserves_original_input() {
    let root = tempfile::tempdir().unwrap();
    let input = json!({"enrichment":true});
    write_run_artifact_json(root.path(), "child", "input.json", "tool input", &input).unwrap();
    let before = fs::read(run_artifact_path(root.path(), "child", "input.json")).unwrap();
    retain_inherited_allowance(root.path(), "child", &work()).unwrap();
    let artifact = fs::read(run_artifact_path(root.path(), "child", LEAF)).unwrap();
    retain_inherited_allowance(root.path(), "child", &work()).unwrap();
    assert_eq!(
        artifact,
        fs::read(run_artifact_path(root.path(), "child", LEAF)).unwrap()
    );
    assert_eq!(
        before,
        fs::read(run_artifact_path(root.path(), "child", "input.json")).unwrap()
    );
    let read = load(root.path(), "child").unwrap().unwrap();
    assert_eq!(read.accounting_run_id, "owned-parent");
    assert_eq!(read.work, InvestigationWork::Review);
    assert_eq!(read.reference.investigation_id, "owned-study");
}

#[test]
fn another_binding_cannot_replace_retained_accounting() {
    let root = tempfile::tempdir().unwrap();
    retain_inherited_allowance(root.path(), "child", &work()).unwrap();
    let before = fs::read(run_artifact_path(root.path(), "child", LEAF)).unwrap();
    let mut changed = work();
    changed.run_id = "another-parent".into();
    assert!(retain_inherited_allowance(root.path(), "child", &changed).is_err());
    assert_eq!(
        before,
        fs::read(run_artifact_path(root.path(), "child", LEAF)).unwrap()
    );
}

#[test]
fn missing_and_changed_retained_bytes_are_not_absent_legacy_context() {
    let root = tempfile::tempdir().unwrap();
    assert!(load(root.path(), "child").unwrap().is_none());
    retain_inherited_allowance(root.path(), "child", &work()).unwrap();
    let path = run_artifact_path(root.path(), "child", LEAF);
    fs::write(&path, "{}").unwrap();
    assert!(load(root.path(), "child")
        .unwrap_err()
        .to_string()
        .contains("changed since retention"));
    fs::remove_file(&path).unwrap();
    assert!(load(root.path(), "child")
        .unwrap_err()
        .to_string()
        .contains("missing after retention"));
    assert!(retain_inherited_allowance(root.path(), "child", &work()).is_err());
}

#[test]
fn unregistered_bytes_and_oversized_context_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    ensure_run_artifact_parent(root.path(), "child", LEAF).unwrap();
    let path = run_artifact_path(root.path(), "child", LEAF);
    fs::write(&path, "{}").unwrap();
    assert!(load(root.path(), "child").is_err());
    fs::write(&path, vec![b' '; MAX_BYTES + 1]).unwrap();
    assert!(load(root.path(), "child").is_err());
}

#[test]
fn authenticated_wrong_identity_and_unknown_fields_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    retain_inherited_allowance(root.path(), "child", &work()).unwrap();
    let original = serde_json::to_value(load(root.path(), "child").unwrap().unwrap()).unwrap();
    for (key, value) in [
        ("schemaVersion", json!(2)),
        ("runId", json!("another")),
        ("accountingRunId", json!("../outside")),
        ("extraApproval", json!(true)),
    ] {
        let mut invalid = original.clone();
        invalid[key] = value;
        write_run_artifact_json(
            root.path(),
            "child",
            LEAF,
            "Inherited accounting context",
            &invalid,
        )
        .unwrap();
        assert!(load(root.path(), "child").is_err(), "{key}");
    }
}

#[test]
fn concurrent_different_bindings_cannot_both_publish() {
    let root = tempfile::tempdir().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = (0..2)
        .map(|index| {
            let path = root.path().to_path_buf();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut candidate = work();
                candidate.work_id = format!("work-{index}");
                barrier.wait();
                retain_inherited_allowance(&path, "child", &candidate).is_ok()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|success| *success)
            .count(),
        1
    );
    assert!(load(root.path(), "child").unwrap().is_some());
}

#[cfg(unix)]
#[test]
fn linked_context_cannot_read_outside_the_run_bundle() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    ensure_run_artifact_parent(root.path(), "child", LEAF).unwrap();
    std::os::unix::fs::symlink(
        outside.path(),
        run_artifact_path(root.path(), "child", LEAF),
    )
    .unwrap();
    assert!(load(root.path(), "child").is_err());
}
