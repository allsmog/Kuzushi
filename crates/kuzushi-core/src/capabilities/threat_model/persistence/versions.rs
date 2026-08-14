//! Workspace-level API over the append-only threat-model version ledger in
//! `.kuzushi/v3/index.sqlite3`. The flat `.kuzushi/threat-model.json` stays
//! the live interface; the ledger records every persisted document so
//! operators can inspect history and re-select an earlier model.

use super::*;
use crate::findings::{FindingStore, ThreatModelVersionRecord};
use crate::WorkspaceTarget;

/// Append the just-persisted document to the version ledger. Identical
/// re-saves deduplicate against the latest row; returns the new row id.
pub fn record_threat_model_version(
    root: &Path,
    document: &Value,
    source: &str,
    run_id: Option<&str>,
) -> Result<Option<i64>> {
    let store = open_ledger_store(root)?;
    store.record_threat_model_version(document, source, run_id)
}

/// Newest-first version summaries; empty when no ledger exists yet.
pub fn list_threat_model_versions(
    root: &Path,
    limit: usize,
) -> Result<Vec<ThreatModelVersionRecord>> {
    let workspace = WorkspaceTarget::new(root)?;
    let path = workspace.findings_db_path();
    if !path.is_file() {
        return Ok(Vec::new());
    }
    FindingStore::open_read_only(path)?.list_threat_model_versions(limit)
}

/// Make a stored version the live `.kuzushi/threat-model.json`. The current
/// live document is snapshotted into the ledger first (source
/// `pre-restore`), so an operator-edited model is never lost, then the
/// restored document is appended as a `restore` row.
pub fn restore_threat_model_version(root: &Path, id: i64) -> Result<ThreatModelVersionRecord> {
    let store = open_ledger_store(root)?;
    let summary = store
        .threat_model_version_summary(id)?
        .with_context(|| format!("threat-model version {id} not found"))?;
    let mut document = store
        .threat_model_version_document(id)?
        .with_context(|| format!("threat-model version {id} not found"))?;
    if let Some(live) = load_persistent_threat_model(root) {
        store.record_threat_model_version(&live, "pre-restore", None)?;
    }
    // A restored document may predate the current checkout; re-verify so
    // consumers see an honest staleness verdict instead of blind trust.
    let verification = verify_threat_model_document(&document, root)?;
    stamp_verification(&mut document, &verification);
    save_persistent_threat_model(root, &document, true)?;
    store.record_threat_model_version(&document, "restore", None)?;
    Ok(summary)
}

/// Content hash of the live persistent threat model, for marking which
/// ledger row is currently live. None when no live document exists.
pub fn live_threat_model_sha256(root: &Path) -> Option<String> {
    load_persistent_threat_model(root)
        .map(|document| crate::findings::threat_model_document_sha256(&document))
}

fn open_ledger_store(root: &Path) -> Result<FindingStore> {
    let workspace = WorkspaceTarget::new(root)?;
    FindingStore::open(workspace.findings_db_path())
}

#[cfg(test)]
mod version_tests {
    use super::*;
    use serde_json::json;

    fn document(root: &Path, title: &str) -> Value {
        let tree_hash = crate::incremental_index::current_workspace_tree_hash(root).unwrap();
        json!({
            "methodology": "stride",
            "threats": [{"id": "T-001", "title": title}],
            "provenance": {"treeHash": tree_hash},
        })
    }

    #[test]
    fn list_without_ledger_is_empty_and_creates_nothing() {
        let workspace = tempfile::tempdir().unwrap();

        let versions = list_threat_model_versions(workspace.path(), 10).unwrap();

        assert!(versions.is_empty());
        assert!(!workspace.path().join(".kuzushi/v3").exists());
    }

    #[test]
    fn record_then_list_round_trips_summaries() {
        let workspace = tempfile::tempdir().unwrap();

        let id = record_threat_model_version(
            workspace.path(),
            &document(workspace.path(), "one"),
            "build",
            None,
        )
        .unwrap()
        .unwrap();
        let versions = list_threat_model_versions(workspace.path(), 10).unwrap();

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].id, id);
        assert_eq!(versions[0].source, "build");
        assert_eq!(versions[0].threat_count, 1);
    }

    #[test]
    fn restore_makes_the_selected_version_live_and_keeps_history() {
        let workspace = tempfile::tempdir().unwrap();
        let original = document(workspace.path(), "original");
        let newer = document(workspace.path(), "newer");
        let original_id =
            record_threat_model_version(workspace.path(), &original, "build", None)
                .unwrap()
                .unwrap();
        record_threat_model_version(workspace.path(), &newer, "build", None).unwrap();
        save_persistent_threat_model(workspace.path(), &newer, true).unwrap();

        let restored = restore_threat_model_version(workspace.path(), original_id).unwrap();

        assert_eq!(restored.id, original_id);
        let mut live = load_persistent_threat_model(workspace.path()).unwrap();
        assert!(
            live.as_object_mut().unwrap().remove("verification").is_some(),
            "restore re-verifies the document"
        );
        assert_eq!(live, original);
        assert_eq!(
            live_threat_model_sha256(workspace.path()).unwrap(),
            restored.sha256
        );
        // ledger: original, newer, restore-of-original (live == newer, so the
        // pre-restore snapshot deduped against the latest row)
        let versions = list_threat_model_versions(workspace.path(), 10).unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].source, "restore");
    }

    #[test]
    fn restore_snapshots_an_edited_live_document_first() {
        let workspace = tempfile::tempdir().unwrap();
        let recorded = document(workspace.path(), "recorded");
        let id = record_threat_model_version(workspace.path(), &recorded, "build", None)
            .unwrap()
            .unwrap();
        // Live document diverged from the ledger (operator hand-edit).
        let edited = document(workspace.path(), "hand-edited");
        save_persistent_threat_model(workspace.path(), &edited, true).unwrap();

        restore_threat_model_version(workspace.path(), id).unwrap();

        let versions = list_threat_model_versions(workspace.path(), 10).unwrap();
        assert!(
            versions.iter().any(|version| version.source == "pre-restore"),
            "edited live document must be snapshotted before restore"
        );
        let mut live = load_persistent_threat_model(workspace.path()).unwrap();
        live.as_object_mut().unwrap().remove("verification");
        assert_eq!(live, recorded);
    }

    /// A snapshot whose recorded repository identity no longer resolves
    /// against the target it describes.
    fn write_stale_context_snapshot(workspace: &Path) {
        let path = crate::context::context_snapshot_path(workspace);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let snapshot = json!({
            "target": workspace.canonicalize().unwrap().display().to_string(),
            "timestamp": 9,
            "provenance": {
                "revision": "0000000000000000000000000000000000000000",
                "revisionDirty": false,
            },
            "attackSurfaceMap": {"surfaces": []},
        });
        std::fs::write(&path, serde_json::to_string_pretty(&snapshot).unwrap()).unwrap();
    }

    #[test]
    fn restore_survives_a_stale_context_snapshot_and_discloses_it() {
        let workspace = tempfile::tempdir().unwrap();
        let stored = document(workspace.path(), "stored");
        let id = record_threat_model_version(workspace.path(), &stored, "build", None)
            .unwrap()
            .unwrap();
        write_stale_context_snapshot(workspace.path());

        restore_threat_model_version(workspace.path(), id).unwrap();

        let live = load_persistent_threat_model(workspace.path()).unwrap();
        let verification = live.pointer("/verification").unwrap();
        assert_eq!(verification.pointer("/groundingSource").unwrap(), "noncatalog");
        assert!(
            verification
                .pointer("/groundingDegraded")
                .and_then(Value::as_str)
                .is_some_and(|disclosure| disclosure.contains("context:build")),
            "restore must disclose why the catalog did not ground it: {verification}"
        );
    }

    #[test]
    fn restore_of_unknown_version_fails_without_touching_live_model() {
        let workspace = tempfile::tempdir().unwrap();
        let live = document(workspace.path(), "live");
        save_persistent_threat_model(workspace.path(), &live, true).unwrap();

        let error = restore_threat_model_version(workspace.path(), 42).unwrap_err();

        assert!(error.to_string().contains("not found"));
        assert_eq!(
            load_persistent_threat_model(workspace.path()).unwrap(),
            live
        );
    }
}
