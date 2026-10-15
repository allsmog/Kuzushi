use super::*;

fn record(target: &Path, session: &str, text: &str) -> ContextDraftRecord {
    ContextDraftRecord {
        version: 1, target: target.into(), session_id: session.into(), saved_at_seconds: 0,
        source: serde_json::from_value(serde_json::json!({"modelId":format!("tm_{}", "a".repeat(32)),"revisionId":format!("tmr_{}", "b".repeat(32)),"sha256":format!("sha256:{}", "c".repeat(64))})).unwrap(),
        snapshot: Some(ContextDraftSnapshot {
            name: DraftText { text: "Unaccepted copy".into(), cursor: 3 },
            fields: vec![ContextDraftField { pointer: "/systemContext".into(), text: Some(text.into()), cursor: 1 }],
            selected_pointer: Some("/systemContext".into()), scroll: 2,
            mode: ContextDraftMode::Writing, origin_hashes: vec![],
        }), resolved_hashes: vec![],
    }
}

fn fixture() -> (tempfile::TempDir, ContextDraftStore, ContextDraftRecord) {
    let root = tempfile::tempdir().unwrap();
    let store = ContextDraftStore::from_sessions_root(root.path().join(".kuzushi/sessions"));
    let data = record(
        root.path(),
        "00000000-0000-4000-8000-000000000001",
        "α\n東京",
    );
    (root, store, data)
}

#[test]
fn checkpoint_restores_exact_private_text_and_cursor_without_work_authority() {
    let (_root, store, data) = fixture();
    store.write(&data).unwrap();
    let recovered = store.recover(&data.target, &data.source).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].record, data);
    let encoded = serde_json::to_value(data).unwrap();
    for key in ["model", "allowance", "jobs", "activated"] {
        assert!(encoded.get(key).is_none());
    }
}

#[test]
fn resolved_exact_record_does_not_erase_another_sessions_later_edit() {
    let (_root, store, mut first) = fixture();
    store.write(&first).unwrap();
    let original = store
        .recover(&first.target, &first.source)
        .unwrap()
        .remove(0);
    let mut second = first.clone();
    second.session_id = "00000000-0000-4000-8000-000000000002".into();
    second.snapshot = None;
    second.resolved_hashes = vec![original.record_hash];
    store.write(&second).unwrap();
    assert!(store
        .recover(&first.target, &first.source)
        .unwrap()
        .is_empty());
    first.snapshot.as_mut().unwrap().name.text = "Independent new edit".into();
    store.write(&first).unwrap();
    assert_eq!(
        store.recover(&first.target, &first.source).unwrap()[0].record,
        first
    );
    second.snapshot = first.snapshot.clone();
    second.resolved_hashes.clear();
    store.write(&second).unwrap();
    assert_eq!(
        store.recover(&first.target, &first.source).unwrap().len(),
        2
    );
}

#[test]
fn target_and_revision_membership_do_not_fall_back() {
    let (root, store, data) = fixture();
    store.write(&data).unwrap();
    assert!(store
        .recover(&root.path().join("other"), &data.source)
        .unwrap()
        .is_empty());
    let mut changed = data.clone();
    changed.source.sha256 = format!("sha256:{}", "d".repeat(64));
    assert!(store
        .recover(&data.target, &changed.source)
        .unwrap()
        .is_empty());
}

#[test]
fn malformed_version_and_foreign_identity_preserve_original_file() {
    let (_root, store, data) = fixture();
    store.write(&data).unwrap();
    let path = store
        .directory(&data.target, &data.source)
        .unwrap()
        .join(format!("{}.json", data.session_id));
    for field in ["version", "target", "model"] {
        let mut value = serde_json::to_value(&data).unwrap();
        value[field] = match field {
            "version" => serde_json::json!(2),
            "target" => serde_json::json!("/other"),
            _ => serde_json::json!("unapproved"),
        };
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(store.recover(&data.target, &data.source).is_err());
        assert!(store.write(&data).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn crash_before_publication_keeps_the_previous_checkpoint() {
    let (_root, store, mut data) = fixture();
    store.write(&data).unwrap();
    let path = store
        .directory(&data.target, &data.source)
        .unwrap()
        .join(format!("{}.json", data.session_id));
    let before = fs::read(&path).unwrap();
    let _fault = crate::fs_atomic::inject_atomic_write_fault(
        path.clone(),
        crate::fs_atomic::AtomicWriteFaultPoint::AfterTempSync,
    );
    data.snapshot.as_mut().unwrap().name.text = "Interrupted new checkpoint".into();
    assert!(store.write(&data).is_err());
    assert_eq!(fs::read(path).unwrap(), before);
    assert_eq!(
        store.recover(&data.target, &data.source).unwrap()[0]
            .record
            .snapshot
            .as_ref()
            .unwrap()
            .name
            .text,
        "Unaccepted copy"
    );
}

#[test]
fn checkpoint_rejects_out_of_range_cursor_and_oversize_fields() {
    let (_root, store, mut data) = fixture();
    data.snapshot.as_mut().unwrap().fields[0].cursor = 99;
    assert!(store.write(&data).is_err());
    data.snapshot.as_mut().unwrap().fields[0].cursor = 1;
    data.snapshot.as_mut().unwrap().fields[0].text = Some("x".repeat(16 * 1024 + 1));
    assert!(store.write(&data).is_err());
}

#[test]
fn full_directory_refuses_more_sessions_and_retains_existing_checkpoint() {
    let (_root, store, mut data) = fixture();
    store.write(&data).unwrap();
    let directory = store.directory(&data.target, &data.source).unwrap();
    let before = fs::read(directory.join(format!("{}.json", data.session_id))).unwrap();
    for index in 1..MAX_RECORDS {
        fs::write(directory.join(format!("retained-{index}.tmp")), []).unwrap();
    }
    data.session_id = "00000000-0000-4000-8000-000000000002".into();
    assert!(store.write(&data).unwrap_err().to_string().contains("full"));
    assert_eq!(
        fs::read(directory.join("00000000-0000-4000-8000-000000000001.json")).unwrap(),
        before
    );
    fs::write(directory.join("one-more.tmp"), []).unwrap();
    assert!(store
        .recover(&data.target, &data.source)
        .unwrap_err()
        .to_string()
        .contains("limit"));
}

#[test]
fn unknown_fields_and_recovery_chain_limits_are_honest() {
    let (_root, store, mut data) = fixture();
    let mut value = serde_json::to_value(&data).unwrap();
    value["allowance"] = serde_json::json!("approved");
    assert!(serde_json::from_value::<ContextDraftRecord>(value).is_err());
    data.snapshot.as_mut().unwrap().origin_hashes = vec!["a".repeat(64); 33];
    assert!(store
        .write(&data)
        .unwrap_err()
        .to_string()
        .contains("chain"));
}

#[cfg(unix)]
#[test]
fn private_permissions_and_unsafe_paths_are_enforced() {
    use std::os::unix::{fs::symlink, fs::PermissionsExt};
    let (root, store, data) = fixture();
    store.write(&data).unwrap();
    let directory = store.directory(&data.target, &data.source).unwrap();
    let path = directory.join(format!("{}.json", data.session_id));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    fs::remove_file(&path).unwrap();
    symlink(root.path().join("elsewhere"), &path).unwrap();
    assert!(store.recover(&data.target, &data.source).is_err());
    assert!(store.write(&data).is_err());
}
