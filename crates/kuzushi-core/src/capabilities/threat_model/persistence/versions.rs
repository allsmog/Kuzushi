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

/// Append a version row bound to the immutable model revision that owns the
/// document. Equal content under another revision remains a distinct ledger
/// event; retrying the same revision deduplicates.
pub fn record_threat_model_version_with_ref(
    root: &Path,
    document: &Value,
    source: &str,
    run_id: Option<&str>,
    model_ref: &ThreatModelRef,
) -> Result<Option<i64>> {
    let store = open_ledger_store(root)?;
    store.record_threat_model_version_with_ref(
        document,
        source,
        run_id,
        model_ref.model_id.as_str(),
        model_ref.revision_id.as_str(),
    )
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

/// Compatibility adapter for the old numeric version picker. The selected
/// ledger row is restored through the authoritative immutable-revision store;
/// the compatibility mirror is never written independently.
pub fn restore_threat_model_version(root: &Path, id: i64) -> Result<ThreatModelVersionRecord> {
    let store = open_ledger_store(root)?;
    let summary = store
        .threat_model_version_summary(id)?
        .with_context(|| format!("threat-model version {id} not found"))?;
    let committed = match typed_ledger_revision(&summary)? {
        Some((model_id, revision_id)) => {
            let committed = restore_threat_model_revision(root, &revision_id, "tui:threats-use")?;
            anyhow::ensure!(
                committed.model_ref.model_id == model_id,
                "threat-model ledger version {id} names a revision from another lineage"
            );
            committed
        }
        None => import_and_restore_legacy_ledger_version(root, &store, &summary)?,
    };
    let restored = load_threat_model_revision(
        root,
        &committed.model_ref.model_id,
        Some(&committed.model_ref.revision_id),
    )?;
    store.record_threat_model_version_with_ref(
        &restored.document,
        "restore",
        None,
        committed.model_ref.model_id.as_str(),
        committed.model_ref.revision_id.as_str(),
    )?;
    Ok(summary)
}

fn typed_ledger_revision(
    summary: &ThreatModelVersionRecord,
) -> Result<Option<(ThreatModelId, ThreatModelRevisionId)>> {
    match (&summary.model_id, &summary.revision_id) {
        (Some(model_id), Some(revision_id)) => Ok(Some((
            ThreatModelId::parse(model_id)?,
            ThreatModelRevisionId::parse(revision_id)?,
        ))),
        (None, None) => Ok(None),
        _ => anyhow::bail!(
            "threat-model ledger version {} has incomplete immutable model identity",
            summary.id
        ),
    }
}

fn import_and_restore_legacy_ledger_version(
    root: &Path,
    store: &FindingStore,
    summary: &ThreatModelVersionRecord,
) -> Result<ThreatModelCommitResult> {
    let raw = store
        .threat_model_version_document(summary.id)?
        .with_context(|| format!("threat-model version {} not found", summary.id))?;
    let methodology = legacy_methodology(summary, &raw);
    let mut document = crate::capabilities::threat_model::normalize_document(raw, &methodology)?;
    crate::capabilities::threat_model::require_complete_security_context_links(&document)?;
    let verification = verify_threat_model_document(&document, root)?;
    stamp_verification(&mut document, &verification);
    let historical = commit_threat_model_revision(
        root,
        &document,
        ThreatModelCommit {
            model_id: None,
            new_model: true,
            label: format!("Imported legacy {} model", methodology.to_ascii_uppercase()),
            scope: crate::capabilities::threat_model::root_scope_ref(root)?,
            methodology,
            source: ThreatModelRevisionSource::LegacyImport,
            source_revision_id: None,
            run_id: None,
            activate: Some(false),
            actor: "tui:threats-use:migrate".to_string(),
        },
    )?;
    restore_threat_model_revision(root, &historical.model_ref.revision_id, "tui:threats-use")
}

fn legacy_methodology(summary: &ThreatModelVersionRecord, document: &Value) -> String {
    document
        .get("methodology")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&summary.methodology)
        .trim()
        .to_ascii_lowercase()
}

/// Content hash of the live persistent threat model, for marking which
/// ledger row is currently live. None when no live document exists.
pub fn live_threat_model_sha256(root: &Path) -> Result<Option<String>> {
    try_live_threat_model_sha256(root)
}

/// Result-returning live digest for production callers. Integrity failures
/// remain distinguishable from a workspace with no active model.
pub fn try_live_threat_model_sha256(root: &Path) -> Result<Option<String>> {
    Ok(try_load_persistent_threat_model(root)?
        .map(|document| crate::findings::threat_model_document_sha256(&document)))
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
            "version": "2.0",
            "methodology": "stride",
            "dfd": {
                "nodes": [{"id": "app", "name": "Application"}],
                "flows": [],
                "trustBoundaries": []
            },
            "threats": [{
                "id": "T-001",
                "title": title,
                "targetElementIds": ["app"]
            }],
            "summary": {},
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
    fn ref_aware_recording_round_trips_typed_model_identity() {
        let workspace = tempfile::tempdir().unwrap();
        let model_ref = ThreatModelRef {
            model_id: ThreatModelId::new(),
            revision_id: ThreatModelRevisionId::new(),
            sha256: format!("sha256:{}", "a".repeat(64)),
        };

        record_threat_model_version_with_ref(
            workspace.path(),
            &document(workspace.path(), "revisioned"),
            "build",
            Some("run-ref"),
            &model_ref,
        )
        .unwrap();
        let versions = list_threat_model_versions(workspace.path(), 10).unwrap();

        assert_eq!(
            versions[0].model_id.as_deref(),
            Some(model_ref.model_id.as_str())
        );
        assert_eq!(
            versions[0].revision_id.as_deref(),
            Some(model_ref.revision_id.as_str())
        );
    }

    #[test]
    fn restore_makes_the_selected_version_live_and_keeps_history() {
        let workspace = tempfile::tempdir().unwrap();
        let original = document(workspace.path(), "original");
        let newer = document(workspace.path(), "newer");
        let original_id = record_threat_model_version(workspace.path(), &original, "build", None)
            .unwrap()
            .unwrap();
        record_threat_model_version(workspace.path(), &newer, "build", None).unwrap();
        save_persistent_threat_model(workspace.path(), &newer, true).unwrap();

        let restored = restore_threat_model_version(workspace.path(), original_id).unwrap();

        assert_eq!(restored.id, original_id);
        let mut live = load_persistent_threat_model(workspace.path())
            .unwrap()
            .unwrap();
        assert!(
            live.as_object_mut()
                .unwrap()
                .remove("verification")
                .is_some(),
            "restore re-verifies the document"
        );
        assert_eq!(live["threats"][0]["title"], original["threats"][0]["title"]);
        // ledger: original, newer, restore-of-original (live == newer, so the
        // pre-restore snapshot deduped against the latest row)
        let versions = list_threat_model_versions(workspace.path(), 10).unwrap();
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].source, "restore");
        let active = load_active_threat_model(workspace.path()).unwrap().unwrap();
        assert_eq!(
            versions[0].model_id.as_deref(),
            Some(active.model_ref.model_id.as_str())
        );
        assert_eq!(
            versions[0].revision_id.as_deref(),
            Some(active.model_ref.revision_id.as_str())
        );
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

        let manifest = load_threat_model_manifest(workspace.path())
            .unwrap()
            .unwrap();
        let preserved_edit = manifest.models.iter().any(|model| {
            load_threat_model_revision(workspace.path(), &model.model_id, None).is_ok_and(
                |revision| {
                    revision.document["threats"][0]["title"] == edited["threats"][0]["title"]
                },
            )
        });
        assert!(
            preserved_edit,
            "the migrated hand edit must remain immutable history"
        );
        let mut live = load_persistent_threat_model(workspace.path())
            .unwrap()
            .unwrap();
        live.as_object_mut().unwrap().remove("verification");
        assert_eq!(live["threats"][0]["title"], recorded["threats"][0]["title"]);
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

        let live = load_persistent_threat_model(workspace.path())
            .unwrap()
            .unwrap();
        let verification = live.pointer("/verification").unwrap();
        assert_eq!(
            verification.pointer("/groundingSource").unwrap(),
            "noncatalog"
        );
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
            load_persistent_threat_model(workspace.path())
                .unwrap()
                .unwrap(),
            live
        );
    }
}
