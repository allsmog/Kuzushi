//! Authoritative threat-model lineage/revision store.
//!
//! The manifest is the commit point. Content objects are immutable and the
//! flat `.kuzushi/threat-model.json` file is only a compatibility mirror.

use crate::capabilities::threat_model::{
    validate_legacy_threat_model, validate_persisted_threat_model,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const STORE_SCHEMA_VERSION: u32 = 1;
const STORE_DIR: &str = "threat-models";
const OBJECTS_DIR: &str = "objects";
const MANIFEST_FILE: &str = "manifest.json";
const ACTIVATIONS_FILE: &str = "activations.jsonl";
const MIRROR_COMMIT_FILE: &str = "mirror-commit.json";
const STORE_LOCK: &str = ".store.lock";
const MAX_STORE_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_ACTIVATION_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ACTIVATION_LINE_BYTES: usize = 64 * 1024;

mod activation;
mod adoption;
mod diff;
mod mirror_commit;
mod query;
mod read_lease;
mod recovery;
mod revision;
mod storage;
mod types;

use activation::*;
use adoption::*;
pub use diff::inspect_threat_model_mirror_diff;
use mirror_commit::*;
pub use query::{
    load_active_threat_model, load_build_threat_model, load_scope_threat_model,
    load_threat_model_by_selector, load_threat_model_manifest, load_threat_model_revision,
    resolve_unique_build_lineage,
};
pub(crate) use read_lease::{
    acquire_exact_threat_model_read_lease, acquire_threat_model_read_lease, ThreatModelReadLease,
};
use recovery::*;
use revision::*;
use storage::*;
pub use types::*;

pub fn threat_model_store_path(root: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(root).join(STORE_DIR)
}

pub fn threat_model_manifest_path(root: &Path) -> PathBuf {
    threat_model_store_path(root).join(MANIFEST_FILE)
}

pub fn threat_model_object_path(root: &Path, sha256: &str) -> Result<PathBuf> {
    object_path(root, sha256)
}

pub fn open_writable_threat_model_store(root: &Path) -> Result<ThreatModelManifest> {
    prepare_store_directories(root)?;
    let _guard = acquire_store_lock(root)?;
    let manifest = load_or_migrate_manifest_locked(root)?;
    reconcile_locked(root, &manifest)?;
    Ok(manifest)
}

pub fn commit_threat_model_revision(
    root: &Path,
    document: &Value,
    request: ThreatModelCommit,
) -> Result<ThreatModelCommitResult> {
    validate_persisted_threat_model(document, &request.methodology)?;
    prepare_store_directories(root)?;
    let _guard = acquire_store_lock(root)?;
    let mut manifest = load_or_migrate_manifest_locked(root)?;
    reconcile_locked(root, &manifest)?;
    let object = write_object(root, document)?;
    let model_ref = append_requested_revision(&mut manifest, document, &object.sha256, &request)?;
    let activate = should_activate_revision(&manifest, &model_ref, request.activate);
    commit_manifest_update(
        root,
        manifest,
        activate.then_some(model_ref.clone()),
        &request.actor,
        activation_source(&request.source),
        None,
    )?;
    Ok(ThreatModelCommitResult {
        model_ref,
        activated: activate,
    })
}

pub fn activate_threat_model(
    root: &Path,
    model_id: &ThreatModelId,
    revision_id: Option<&ThreatModelRevisionId>,
    actor: &str,
    mirror_action: MirrorAction,
) -> Result<ThreatModelRef> {
    prepare_store_directories(root)?;
    let _guard = acquire_store_lock(root)?;
    let manifest = load_or_migrate_manifest_locked(root)?;
    let discarded = reconcile_for_activation(root, &manifest, mirror_action)?;
    let model_ref = resolve_manifest_ref(&manifest, model_id, revision_id)?;
    let source = if discarded.is_some() {
        ActivationSource::DiscardForce
    } else {
        ActivationSource::Activate
    };
    commit_manifest_update(
        root,
        manifest,
        Some(model_ref.clone()),
        actor,
        source,
        discarded,
    )?;
    Ok(model_ref)
}

pub fn restore_threat_model_revision(
    root: &Path,
    revision_id: &ThreatModelRevisionId,
    actor: &str,
) -> Result<ThreatModelCommitResult> {
    let manifest = load_threat_model_manifest(root)?.context("threat-model manifest is missing")?;
    let (model, historical) = find_revision_owner(&manifest, revision_id)?;
    let document = read_object(root, &historical.sha256)?;
    commit_threat_model_revision(
        root,
        &document,
        commit_request_for_restore(model, revision_id, actor),
    )
}

pub(crate) fn apply_threat_model_patch_to_active(
    root: &Path,
    patch: &Value,
    actor: &str,
) -> Result<(ThreatModelCommitResult, Value)> {
    prepare_store_directories(root)?;
    let _guard = acquire_store_lock(root)?;
    let mut manifest = load_or_migrate_manifest_locked(root)?;
    reconcile_locked(root, &manifest)?;
    let active = manifest
        .active
        .clone()
        .context("no active threat model to patch")?;
    let model = manifest
        .models
        .iter()
        .find(|model| model.model_id == active.model_id)
        .cloned()
        .context("active threat-model lineage is absent from manifest")?;
    let mut document = read_object(root, &active.sha256)?;
    merge_json_patch(&mut document, patch);
    validate_persisted_threat_model(&document, &model.methodology)?;
    let object = write_object(root, &document)?;
    let request = operator_edit_request(&model, &active, actor);
    let model_ref = append_requested_revision(&mut manifest, &document, &object.sha256, &request)?;
    commit_manifest_update(
        root,
        manifest,
        Some(model_ref.clone()),
        actor,
        ActivationSource::OperatorEdit,
        None,
    )?;
    Ok((activated_commit_result(model_ref), document))
}

fn activated_commit_result(model_ref: ThreatModelRef) -> ThreatModelCommitResult {
    ThreatModelCommitResult {
        model_ref,
        activated: true,
    }
}

fn operator_edit_request(
    model: &ThreatModelMetadata,
    active: &ThreatModelRef,
    actor: &str,
) -> ThreatModelCommit {
    ThreatModelCommit {
        model_id: Some(model.model_id.clone()),
        new_model: false,
        label: model.label.clone(),
        scope: model.scope.clone(),
        methodology: model.methodology.clone(),
        source: ThreatModelRevisionSource::OperatorEdit,
        source_revision_id: Some(active.revision_id.clone()),
        run_id: None,
        activate: Some(true),
        actor: actor.to_string(),
    }
}

fn merge_json_patch(target: &mut Value, patch: &Value) {
    let Value::Object(patch_fields) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(serde_json::Map::new());
    }
    let target_fields = target.as_object_mut().expect("target was made an object");
    for (key, value) in patch_fields {
        if value.is_null() {
            target_fields.remove(key);
        } else {
            merge_json_patch(
                target_fields.entry(key.clone()).or_insert(Value::Null),
                value,
            );
        }
    }
}

pub fn adopt_threat_model_mirror_edits(
    root: &Path,
    actor: &str,
) -> Result<ThreatModelCommitResult> {
    prepare_store_directories(root)?;
    let _guard = acquire_store_lock(root)?;
    let mut manifest = read_manifest(root)?.context("threat-model manifest is missing")?;
    validate_manifest(root, &manifest)?;
    ensure_activation_audit(root, &manifest)?;
    adopt_mirror_locked(root, &mut manifest, actor)
}

pub fn list_threat_model_heads(root: &Path) -> Result<Vec<(ThreatModelMetadata, ThreatModelRef)>> {
    let Some(manifest) = load_threat_model_manifest(root)? else {
        return Ok(Vec::new());
    };
    manifest
        .models
        .into_iter()
        .map(|model| {
            let model_ref = ref_for_revision(&model, &model.head_revision)?;
            Ok((model, model_ref))
        })
        .collect()
}

pub fn list_model_revisions(
    root: &Path,
    model_id: &ThreatModelId,
) -> Result<Vec<ThreatModelRevisionMetadata>> {
    let manifest = load_threat_model_manifest(root)?.context("threat-model manifest is missing")?;
    let model = manifest
        .models
        .iter()
        .find(|model| &model.model_id == model_id)
        .with_context(|| format!("threat model {} was not found", model_id.as_str()))?;
    Ok(model.revisions.iter().rev().cloned().collect())
}

fn validate_typed_id(value: &str, prefix: &str) -> Result<()> {
    let suffix = value
        .strip_prefix(prefix)
        .with_context(|| format!("id {value:?} must start with {prefix:?}"))?;
    anyhow::ensure!(
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "id {value:?} must contain 32 lowercase hexadecimal characters"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scope() -> ScopeRef {
        ScopeRef {
            scope_id: "root".to_string(),
            rel_path: PathBuf::from("."),
            project_model_sha256: format!("sha256:{}", "1".repeat(64)),
            target_revision: "abc123".to_string(),
        }
    }

    fn request() -> ThreatModelCommit {
        ThreatModelCommit {
            model_id: None,
            new_model: false,
            label: "Primary".to_string(),
            scope: scope(),
            methodology: "stride".to_string(),
            source: ThreatModelRevisionSource::Build,
            source_revision_id: None,
            run_id: Some("run-1".to_string()),
            activate: None,
            actor: "test".to_string(),
        }
    }

    fn model_document(label: &str) -> Value {
        json!({
            "version": "2.0",
            "methodology": "stride",
            "title": label,
            "dfd": {
                "nodes": [{"id": "app"}],
                "flows": [],
                "trustBoundaries": []
            },
            "threats": [],
            "summary": {}
        })
    }

    fn object_path_for_document(root: &Path, document: &Value) -> PathBuf {
        let bytes = crate::review_yield::domain::canonical_json_bytes(document).unwrap();
        let sha256 = crate::run_lifecycle::sha256_content_digest(&bytes);
        object_path(root, &sha256).unwrap()
    }

    fn next_request(first: &ThreatModelCommitResult) -> ThreatModelCommit {
        let mut next = request();
        next.model_id = Some(first.model_ref.model_id.clone());
        next
    }

    fn assert_recovered_active(root: &Path, expected: &Value) {
        open_writable_threat_model_store(root).unwrap();
        assert!(!pending_mirror_commit_path(root).exists());
        let active = load_active_threat_model(root).unwrap().unwrap();
        assert_eq!(&active.document, expected);
        assert_eq!(
            super::super::store::try_load_legacy_threat_model(root).unwrap(),
            Some(expected.clone())
        );
        let activations =
            fs::read_to_string(threat_model_store_path(root).join(ACTIVATIONS_FILE)).unwrap();
        assert_eq!(activations.lines().count(), 2);
    }

    #[test]
    fn changed_scope_binding_is_stale_and_a_build_mints_a_new_lineage() {
        let root = tempfile::tempdir().unwrap();
        let first =
            commit_threat_model_revision(root.path(), &model_document("first"), request()).unwrap();
        let mut changed = scope();
        changed.project_model_sha256 = format!("sha256:{}", "2".repeat(64));

        let error = load_scope_threat_model(root.path(), &changed).unwrap_err();
        assert!(error.to_string().contains("scope binding is stale"));

        let mut next = request();
        next.scope = changed;
        let second =
            commit_threat_model_revision(root.path(), &model_document("second"), next).unwrap();
        assert_ne!(first.model_ref.model_id, second.model_ref.model_id);
    }

    #[test]
    fn target_revision_change_appends_to_the_selected_lineage() {
        let root = tempfile::tempdir().unwrap();
        let first =
            commit_threat_model_revision(root.path(), &model_document("first"), request()).unwrap();
        let mut next = request();
        next.model_id = Some(first.model_ref.model_id.clone());
        next.scope.target_revision = "def456".to_string();

        let second =
            commit_threat_model_revision(root.path(), &model_document("second"), next).unwrap();

        assert_eq!(second.model_ref.model_id, first.model_ref.model_id);
        let manifest = load_threat_model_manifest(root.path()).unwrap().unwrap();
        assert_eq!(manifest.models[0].scope.target_revision, "def456");
        assert_eq!(
            manifest.models[0]
                .revisions
                .last()
                .unwrap()
                .scope
                .as_ref()
                .unwrap()
                .target_revision,
            "def456"
        );
    }

    #[test]
    fn first_commit_writes_object_manifest_activation_and_mirror() {
        let root = tempfile::tempdir().unwrap();
        let result =
            commit_threat_model_revision(root.path(), &model_document("first"), request()).unwrap();

        assert!(result.activated);
        let active = load_active_threat_model(root.path()).unwrap().unwrap();
        assert_eq!(active.model_ref, result.model_ref);
        assert_eq!(active.document, model_document("first"));
        assert!(super::super::store::persistent_threat_model_path(root.path()).is_file());
        let activations =
            fs::read_to_string(threat_model_store_path(root.path()).join(ACTIVATIONS_FILE))
                .unwrap();
        assert_eq!(activations.lines().count(), 1);
    }

    #[test]
    fn crash_after_object_creation_leaves_a_harmless_orphan() {
        let root = tempfile::tempdir().unwrap();
        prepare_store_directories(root.path()).unwrap();
        let object = write_object(root.path(), &json!({"title":"orphan"})).unwrap();

        let manifest = open_writable_threat_model_store(root.path()).unwrap();

        assert!(manifest.active.is_none());
        assert!(object_path(root.path(), &object.sha256).unwrap().is_file());
    }

    #[test]
    fn injected_crash_after_object_creation_leaves_a_harmless_orphan() {
        let root = tempfile::tempdir().unwrap();
        let document = model_document("orphan");
        let object_path = object_path_for_document(root.path(), &document);
        {
            let _fault = crate::fs_atomic::inject_atomic_write_fault(
                object_path.clone(),
                crate::fs_atomic::AtomicWriteFaultPoint::AfterRename,
            );
            assert!(commit_threat_model_revision(root.path(), &document, request()).is_err());
        }

        let manifest = open_writable_threat_model_store(root.path()).unwrap();
        assert!(manifest.active.is_none());
        assert!(object_path.is_file());
    }

    #[test]
    fn crash_before_manifest_rename_ignores_the_temp_generation() {
        let root = tempfile::tempdir().unwrap();
        prepare_store_directories(root.path()).unwrap();
        let temp = threat_model_store_path(root.path()).join(".manifest.json.tmp-fault");
        fs::write(&temp, r#"{"schemaVersion":1,"generation":99,"models":[]}"#).unwrap();

        let manifest = open_writable_threat_model_store(root.path()).unwrap();

        assert_eq!(manifest.generation, 0);
        assert!(manifest.active.is_none());
    }

    #[test]
    fn injected_crash_after_manifest_temp_write_keeps_the_previous_generation() {
        let root = tempfile::tempdir().unwrap();
        let document = model_document("uncommitted");
        {
            let _fault = crate::fs_atomic::inject_atomic_write_fault(
                threat_model_manifest_path(root.path()),
                crate::fs_atomic::AtomicWriteFaultPoint::AfterTempSync,
            );
            assert!(commit_threat_model_revision(root.path(), &document, request()).is_err());
        }

        let manifest = open_writable_threat_model_store(root.path()).unwrap();
        assert_eq!(manifest.generation, 0);
        assert!(manifest.active.is_none());
    }

    #[test]
    fn crash_before_manifest_commit_restores_the_withdrawn_previous_mirror() {
        let root = tempfile::tempdir().unwrap();
        let first =
            commit_threat_model_revision(root.path(), &model_document("first"), request()).unwrap();
        {
            let _fault = crate::fs_atomic::inject_atomic_write_fault(
                threat_model_manifest_path(root.path()),
                crate::fs_atomic::AtomicWriteFaultPoint::AfterTempSync,
            );
            assert!(commit_threat_model_revision(
                root.path(),
                &model_document("uncommitted"),
                next_request(&first),
            )
            .is_err());
        }

        let manifest = open_writable_threat_model_store(root.path()).unwrap();

        assert_eq!(manifest.generation, 1);
        assert_eq!(manifest.active, Some(first.model_ref));
        assert!(!pending_mirror_commit_path(root.path()).exists());
        assert_eq!(
            super::super::store::try_load_legacy_threat_model(root.path()).unwrap(),
            Some(model_document("first"))
        );
    }

    #[test]
    fn injected_crash_after_manifest_rename_repairs_the_previous_managed_mirror() {
        let root = tempfile::tempdir().unwrap();
        let first =
            commit_threat_model_revision(root.path(), &model_document("first"), request()).unwrap();
        let next = model_document("second");
        {
            let _fault = crate::fs_atomic::inject_atomic_write_fault(
                threat_model_manifest_path(root.path()),
                crate::fs_atomic::AtomicWriteFaultPoint::AfterRename,
            );
            assert!(commit_threat_model_revision(root.path(), &next, next_request(&first)).is_err());
        }

        assert_recovered_active(root.path(), &next);
    }

    #[test]
    fn crash_after_manifest_rename_repairs_a_missing_mirror() {
        let root = tempfile::tempdir().unwrap();
        commit_threat_model_revision(root.path(), &model_document("managed"), request()).unwrap();
        fs::remove_file(super::super::store::persistent_threat_model_path(
            root.path(),
        ))
        .unwrap();

        open_writable_threat_model_store(root.path()).unwrap();

        assert_eq!(
            super::super::store::try_load_legacy_threat_model(root.path()).unwrap(),
            Some(model_document("managed"))
        );
    }

    #[test]
    fn crash_before_mirror_rename_repairs_from_the_manifest() {
        let root = tempfile::tempdir().unwrap();
        commit_threat_model_revision(root.path(), &model_document("managed"), request()).unwrap();
        let mirror = super::super::store::persistent_threat_model_path(root.path());
        fs::remove_file(&mirror).unwrap();
        fs::write(
            mirror.with_file_name(".threat-model.json.tmp-fault"),
            b"partial",
        )
        .unwrap();

        open_writable_threat_model_store(root.path()).unwrap();

        assert_eq!(
            super::super::store::try_load_legacy_threat_model(root.path()).unwrap(),
            Some(model_document("managed"))
        );
    }

    #[test]
    fn injected_crash_after_mirror_temp_write_repairs_from_the_manifest() {
        let root = tempfile::tempdir().unwrap();
        let first =
            commit_threat_model_revision(root.path(), &model_document("first"), request()).unwrap();
        let next = model_document("second");
        {
            let _fault = crate::fs_atomic::inject_atomic_write_fault(
                super::super::store::persistent_threat_model_path(root.path()),
                crate::fs_atomic::AtomicWriteFaultPoint::AfterTempSync,
            );
            assert!(commit_threat_model_revision(root.path(), &next, next_request(&first)).is_err());
        }

        assert_recovered_active(root.path(), &next);
    }

    #[test]
    fn injected_crash_after_mirror_rename_opens_the_committed_revision() {
        let root = tempfile::tempdir().unwrap();
        let first =
            commit_threat_model_revision(root.path(), &model_document("first"), request()).unwrap();
        let next = model_document("second");
        {
            let _fault = crate::fs_atomic::inject_atomic_write_fault(
                super::super::store::persistent_threat_model_path(root.path()),
                crate::fs_atomic::AtomicWriteFaultPoint::AfterRename,
            );
            assert!(commit_threat_model_revision(root.path(), &next, next_request(&first)).is_err());
        }

        assert_recovered_active(root.path(), &next);
    }

    #[test]
    fn read_only_open_never_migrates_legacy_mirror() {
        let root = tempfile::tempdir().unwrap();
        super::super::store::save_persistent_threat_model(
            root.path(),
            &json!({"methodology":"stride"}),
            true,
        )
        .unwrap();

        assert!(load_threat_model_manifest(root.path()).unwrap().is_none());
        assert!(!threat_model_store_path(root.path()).exists());
    }

    #[test]
    fn writable_open_imports_legacy_mirror_once() {
        let root = tempfile::tempdir().unwrap();
        super::super::store::save_persistent_threat_model(
            root.path(),
            &json!({"methodology":"pasta"}),
            true,
        )
        .unwrap();

        let first = open_writable_threat_model_store(root.path()).unwrap();
        let second = open_writable_threat_model_store(root.path()).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.generation, 1);
        assert_eq!(first.models[0].methodology, "pasta");
        assert_eq!(
            first.models[0].scope,
            crate::capabilities::threat_model::current_scope_ref_for_path(root.path(), ".")
                .unwrap()
                .unwrap()
        );
        assert_eq!(
            crate::capabilities::threat_model::try_resolve_threat_model(root.path(), ".")
                .unwrap()
                .unwrap()
                .resolved_via,
            crate::capabilities::threat_model::ThreatModelResolvedVia::ScopeModel
        );
    }

    #[test]
    fn writable_open_indexes_methodology_less_legacy_mirror_as_stride() {
        let root = tempfile::tempdir().unwrap();
        let document = json!({"version":"2.0", "legacyMarker":"kept"});
        super::super::store::save_persistent_threat_model(root.path(), &document, true).unwrap();

        let manifest = open_writable_threat_model_store(root.path()).unwrap();

        assert_eq!(manifest.models[0].methodology, "stride");
        assert_eq!(
            super::super::store::try_load_legacy_threat_model(root.path()).unwrap(),
            Some(document),
            "migration indexes legacy content without rewriting it"
        );
    }

    #[test]
    fn divergent_mirror_is_never_overwritten_by_normal_open() {
        let root = tempfile::tempdir().unwrap();
        commit_threat_model_revision(root.path(), &model_document("managed"), request()).unwrap();
        super::super::store::save_persistent_threat_model(
            root.path(),
            &model_document("edited"),
            true,
        )
        .unwrap();

        let error = open_writable_threat_model_store(root.path()).unwrap_err();

        assert!(error.downcast_ref::<ThreatModelStoreError>().is_some());
        assert_eq!(
            super::super::store::try_load_legacy_threat_model(root.path()).unwrap(),
            Some(model_document("edited"))
        );
    }

    #[test]
    fn exact_previous_revision_restored_after_activation_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let first =
            commit_threat_model_revision(root.path(), &model_document("first"), request()).unwrap();
        let second = commit_threat_model_revision(
            root.path(),
            &model_document("second"),
            next_request(&first),
        )
        .unwrap();
        assert!(!pending_mirror_commit_path(root.path()).exists());
        super::super::store::save_persistent_threat_model(
            root.path(),
            &model_document("first"),
            true,
        )
        .unwrap();

        let error = open_writable_threat_model_store(root.path()).unwrap_err();

        assert!(matches!(
            error.downcast_ref::<ThreatModelStoreError>(),
            Some(ThreatModelStoreError::DivergentMirror {
                mirror_sha256,
                active_sha256,
            }) if mirror_sha256 == &first.model_ref.sha256
                && active_sha256 == &second.model_ref.sha256
        ));
        assert!(error.to_string().contains("adopt edits"));
        assert!(error.to_string().contains("inspect diff"));
        assert!(error.to_string().contains("discard --force"));
        assert_eq!(
            super::super::store::try_load_legacy_threat_model(root.path()).unwrap(),
            Some(model_document("first"))
        );
    }

    #[test]
    fn forced_activation_records_discarded_mirror_sha() {
        let root = tempfile::tempdir().unwrap();
        let committed =
            commit_threat_model_revision(root.path(), &model_document("managed"), request())
                .unwrap();
        super::super::store::save_persistent_threat_model(
            root.path(),
            &model_document("edited"),
            true,
        )
        .unwrap();

        activate_threat_model(
            root.path(),
            &committed.model_ref.model_id,
            None,
            "test",
            MirrorAction::Discard,
        )
        .unwrap();

        let manifest = load_threat_model_manifest(root.path()).unwrap().unwrap();
        assert!(manifest
            .last_activation
            .unwrap()
            .discarded_mirror_sha256
            .is_some());
        assert_eq!(
            load_active_threat_model(root.path())
                .unwrap()
                .unwrap()
                .document,
            model_document("managed")
        );
    }

    #[test]
    fn forced_activation_discards_and_audits_a_malformed_mirror() {
        let root = tempfile::tempdir().unwrap();
        let committed =
            commit_threat_model_revision(root.path(), &model_document("managed"), request())
                .unwrap();
        let mirror = super::super::store::persistent_threat_model_path(root.path());
        let malformed = b"{not-json";
        fs::write(&mirror, malformed).unwrap();

        let error = open_writable_threat_model_store(root.path()).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ThreatModelStoreError>(),
            Some(ThreatModelStoreError::UnadoptableMirror { .. })
        ));
        activate_threat_model(
            root.path(),
            &committed.model_ref.model_id,
            None,
            "test",
            MirrorAction::Discard,
        )
        .unwrap();

        let manifest = load_threat_model_manifest(root.path()).unwrap().unwrap();
        assert_eq!(
            manifest.last_activation.unwrap().discarded_mirror_sha256,
            Some(crate::run_lifecycle::sha256_content_digest(malformed))
        );
        assert_eq!(
            super::super::store::try_load_legacy_threat_model(root.path()).unwrap(),
            Some(model_document("managed"))
        );
    }

    #[test]
    fn forced_activation_discards_and_audits_an_oversized_mirror() {
        let root = tempfile::tempdir().unwrap();
        let committed =
            commit_threat_model_revision(root.path(), &model_document("managed"), request())
                .unwrap();
        let mirror = super::super::store::persistent_threat_model_path(root.path());
        fs::File::create(&mirror)
            .unwrap()
            .set_len((MAX_STORE_JSON_BYTES + 1) as u64)
            .unwrap();

        let error = open_writable_threat_model_store(root.path()).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<ThreatModelStoreError>(),
            Some(ThreatModelStoreError::UnadoptableMirror { reason, .. })
                if reason.contains("byte limit")
        ));
        activate_threat_model(
            root.path(),
            &committed.model_ref.model_id,
            None,
            "test",
            MirrorAction::Discard,
        )
        .unwrap();

        let manifest = load_threat_model_manifest(root.path()).unwrap().unwrap();
        assert!(manifest
            .last_activation
            .unwrap()
            .discarded_mirror_sha256
            .is_some());
        assert_eq!(
            super::super::store::try_load_legacy_threat_model(root.path()).unwrap(),
            Some(model_document("managed"))
        );
    }

    #[test]
    fn adopting_hand_edits_appends_and_activates_a_revision() {
        let root = tempfile::tempdir().unwrap();
        let original =
            commit_threat_model_revision(root.path(), &model_document("managed"), request())
                .unwrap();
        super::super::store::save_persistent_threat_model(
            root.path(),
            &model_document("edited"),
            true,
        )
        .unwrap();

        let adopted = adopt_threat_model_mirror_edits(root.path(), "operator").unwrap();

        assert_eq!(adopted.model_ref.model_id, original.model_ref.model_id);
        assert_ne!(
            adopted.model_ref.revision_id,
            original.model_ref.revision_id
        );
        assert_eq!(
            load_active_threat_model(root.path())
                .unwrap()
                .unwrap()
                .document,
            model_document("edited")
        );
        let manifest = load_threat_model_manifest(root.path()).unwrap().unwrap();
        assert_eq!(
            manifest.models[0].revisions.last().unwrap().source,
            ThreatModelRevisionSource::Adopt
        );
    }

    #[test]
    fn restoring_history_mints_a_new_revision_with_source_reference() {
        let root = tempfile::tempdir().unwrap();
        let first =
            commit_threat_model_revision(root.path(), &model_document("first"), request()).unwrap();
        let mut second_request = request();
        second_request.model_id = Some(first.model_ref.model_id.clone());
        commit_threat_model_revision(root.path(), &model_document("second"), second_request)
            .unwrap();

        let restored =
            restore_threat_model_revision(root.path(), &first.model_ref.revision_id, "operator")
                .unwrap();

        assert_ne!(restored.model_ref.revision_id, first.model_ref.revision_id);
        assert_eq!(restored.model_ref.sha256, first.model_ref.sha256);
        let revisions = list_model_revisions(root.path(), &first.model_ref.model_id).unwrap();
        assert_eq!(revisions[0].source, ThreatModelRevisionSource::Restore);
        assert_eq!(
            revisions[0].source_revision_id.as_ref(),
            Some(&first.model_ref.revision_id)
        );
    }

    #[test]
    fn scoped_resolution_preserves_an_activated_historical_revision() {
        let root = tempfile::tempdir().unwrap();
        let current_scope =
            crate::capabilities::threat_model::current_scope_ref_for_path(root.path(), ".")
                .unwrap()
                .unwrap();
        let mut first_request = request();
        first_request.scope = current_scope.clone();
        let first =
            commit_threat_model_revision(root.path(), &model_document("first"), first_request)
                .unwrap();
        let mut second_request = request();
        second_request.scope = current_scope.clone();
        second_request.model_id = Some(first.model_ref.model_id.clone());
        commit_threat_model_revision(root.path(), &model_document("second"), second_request)
            .unwrap();
        activate_threat_model(
            root.path(),
            &first.model_ref.model_id,
            Some(&first.model_ref.revision_id),
            "test",
            MirrorAction::Refuse,
        )
        .unwrap();

        let scoped = load_scope_threat_model(root.path(), &current_scope)
            .unwrap()
            .unwrap();
        let build = load_build_threat_model(root.path(), &current_scope, "stride", None)
            .unwrap()
            .unwrap();
        let resolved =
            crate::capabilities::threat_model::try_resolve_threat_model(root.path(), ".")
                .unwrap()
                .unwrap();

        assert_eq!(scoped.model_ref, first.model_ref);
        assert_eq!(build.model_ref, first.model_ref);
        assert_eq!(resolved.model_ref, Some(first.model_ref));
    }

    #[test]
    fn build_model_selection_is_category_bound_and_explicitly_disambiguated() {
        let root = tempfile::tempdir().unwrap();
        let first =
            commit_threat_model_revision(root.path(), &model_document("first"), request()).unwrap();
        let mut second_request = request();
        second_request.new_model = true;
        second_request.activate = Some(false);
        let second =
            commit_threat_model_revision(root.path(), &model_document("second"), second_request)
                .unwrap();

        let active = load_build_threat_model(root.path(), &scope(), "stride", None)
            .unwrap()
            .unwrap();
        let explicit = load_build_threat_model(
            root.path(),
            &scope(),
            "stride",
            Some(&second.model_ref.model_id),
        )
        .unwrap()
        .unwrap();

        assert_eq!(active.model_ref, first.model_ref);
        assert_eq!(explicit.model_ref, second.model_ref);
        assert!(load_build_threat_model(
            root.path(),
            &scope(),
            "pasta",
            Some(&second.model_ref.model_id),
        )
        .is_err());
    }

    #[test]
    fn missing_active_object_is_a_hard_integrity_error() {
        let root = tempfile::tempdir().unwrap();
        let committed =
            commit_threat_model_revision(root.path(), &model_document("managed"), request())
                .unwrap();
        fs::remove_file(object_path(root.path(), &committed.model_ref.sha256).unwrap()).unwrap();

        let error = load_active_threat_model(root.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("active threat-model object"), "{error}");
    }

    #[test]
    fn corrupt_active_object_is_a_hard_integrity_error() {
        let root = tempfile::tempdir().unwrap();
        let committed =
            commit_threat_model_revision(root.path(), &model_document("managed"), request())
                .unwrap();
        fs::write(
            object_path(root.path(), &committed.model_ref.sha256).unwrap(),
            b"{}",
        )
        .unwrap();

        let error = load_active_threat_model(root.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("failed SHA verification"), "{error}");
    }

    #[test]
    fn future_manifest_major_fails_clearly() {
        let root = tempfile::tempdir().unwrap();
        prepare_store_directories(root.path()).unwrap();
        fs::write(
            threat_model_manifest_path(root.path()),
            r#"{"schemaVersion":2,"generation":0,"models":[]}"#,
        )
        .unwrap();

        let error = load_threat_model_manifest(root.path())
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("unsupported threat-model manifest schemaVersion 2"),
            "{error}"
        );
    }
}
