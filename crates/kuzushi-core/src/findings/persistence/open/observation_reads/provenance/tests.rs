use super::*;
use crate::findings::{Finding, Severity};

fn finding() -> Finding {
    Finding::new_tool(
        "owned-source",
        "greeting",
        "note.txt",
        1,
        None,
        Severity::Info,
        "Labeled observation",
    )
}

#[test]
fn exact_generation_keeps_its_own_source_after_later_observation_and_live_edit() {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let mut ids = Vec::new();
    for (run, text) in [
        ("first", "Owned first greeting\n"),
        ("later", "Owned later greeting\n"),
    ] {
        std::fs::write(root.path().join("note.txt"), text).unwrap();
        store
            .record_run_started(run, root.path(), "completed")
            .unwrap();
        ids.push(store.insert_finding(run, &finding()).unwrap());
    }
    std::fs::write(root.path().join("note.txt"), "Another edit\n").unwrap();
    let first = store.recorded_observation_source(ids[0]).unwrap().unwrap();
    let later = store.recorded_observation_source(ids[1]).unwrap().unwrap();
    assert_eq!(first.generation_id, ids[0]);
    assert_eq!(first.run_id, "first");
    assert_eq!(later.run_id, "later");
    assert_ne!(first.blob_hash, later.blob_hash);
    assert_eq!(first.git_commit, None);
    assert_eq!(later.git_commit, None);
    assert_eq!(
        store
            .read_observation_blob(first.blob_hash.as_ref().unwrap())
            .unwrap()
            .unwrap(),
        b"Owned first greeting\n"
    );
    assert!(store
        .recorded_observation_source(i64::MAX)
        .unwrap()
        .is_none());
}

#[test]
fn missing_snapshot_row_preserves_the_recorded_reference_and_explicit_unknown_fields() {
    let root = tempfile::tempdir().unwrap();
    let store = FindingStore::open_in_memory().unwrap();
    store
        .record_run_started("owned", root.path(), "completed")
        .unwrap();
    let id = store.insert_finding("owned", &finding()).unwrap();
    let source = store.recorded_observation_source(id).unwrap().unwrap();
    assert_eq!(source.schema_version, 1);
    assert_eq!(source.run_id, "owned");
    assert!(!source.snapshot_hash.is_empty());
    assert_eq!(source.tree_hash, None);
    assert_eq!(source.blob_hash, None);
    let json = serde_json::to_value(source).unwrap();
    assert!(json["gitCommit"].is_null());
    assert!(json["gitBranch"].is_null());
    assert!(json["dirtyHash"].is_null());
}

#[test]
fn exact_generation_source_lookup_uses_the_existing_projected_id_index() {
    let store = FindingStore::open_in_memory().unwrap();
    let mut query = store
        .conn
        .prepare(&format!("explain query plan {RECORDED_SOURCE_SQL}"))
        .unwrap();
    let details = query
        .query_map([1i64], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        details
            .iter()
            .any(|detail| detail.contains("idx_finding_observations_projected_id")),
        "{details:?}"
    );
}

#[test]
fn source_reference_reader_rejects_unknown_schema_versions() {
    let root = tempfile::tempdir().unwrap();
    let store = FindingStore::open_in_memory().unwrap();
    store
        .record_run_started("owned", root.path(), "completed")
        .unwrap();
    let id = store.insert_finding("owned", &finding()).unwrap();
    let mut json =
        serde_json::to_value(store.recorded_observation_source(id).unwrap().unwrap()).unwrap();
    json["schemaVersion"] = serde_json::json!(2);
    assert!(serde_json::from_value::<RecordedObservationSource>(json).is_err());
}
