use super::*;

pub(super) fn load_or_migrate_manifest_locked(root: &Path) -> Result<ThreatModelManifest> {
    if let Some(manifest) = read_manifest(root)? {
        validate_manifest(root, &manifest)?;
        return Ok(manifest);
    }
    migrate_legacy_mirror_locked(root)
}

pub(super) fn migrate_legacy_mirror_locked(root: &Path) -> Result<ThreatModelManifest> {
    let Some(document) = super::super::store::try_load_legacy_threat_model(root)? else {
        return Ok(ThreatModelManifest::default());
    };
    validate_legacy_threat_model(&document)?;
    let object = write_object(root, &document)?;
    let manifest = legacy_manifest(root, &document, &object.sha256)?;
    write_manifest(root, &manifest)?;
    ensure_activation_audit(root, &manifest)?;
    write_active_mirror(root, &manifest)?;
    Ok(manifest)
}

fn legacy_manifest(root: &Path, document: &Value, sha256: &str) -> Result<ThreatModelManifest> {
    let model_id = ThreatModelId::new();
    let revision_id = ThreatModelRevisionId::new();
    let model_ref = ThreatModelRef {
        model_id: model_id.clone(),
        revision_id: revision_id.clone(),
        sha256: sha256.to_string(),
    };
    let created_at = now_string();
    let activation = new_activation(
        1,
        model_ref.clone(),
        None,
        "migration",
        ActivationSource::LegacyImport,
        None,
    );
    Ok(ThreatModelManifest {
        schema_version: STORE_SCHEMA_VERSION,
        generation: 1,
        active: Some(model_ref),
        last_activation: Some(activation),
        models: vec![legacy_model(
            root,
            document,
            sha256,
            model_id,
            revision_id,
            created_at,
        )?],
    })
}

fn legacy_model(
    root: &Path,
    document: &Value,
    sha256: &str,
    model_id: ThreatModelId,
    revision_id: ThreatModelRevisionId,
    created_at: String,
) -> Result<ThreatModelMetadata> {
    let methodology = legacy_methodology(document);
    let scope = crate::capabilities::threat_model::current_scope_ref_for_path(root, ".")?
        .context("could not bind the imported legacy model to the current root scope")?;
    Ok(ThreatModelMetadata {
        model_id,
        label: "Legacy threat model".to_string(),
        scope: scope.clone(),
        methodology,
        created_at: created_at.clone(),
        head_revision: revision_id.clone(),
        revisions: vec![legacy_revision(
            document,
            sha256,
            revision_id,
            created_at,
            scope,
        )],
    })
}

fn legacy_methodology(document: &Value) -> String {
    document
        .get("methodology")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|methodology| !methodology.is_empty())
        .unwrap_or("stride")
        .to_ascii_lowercase()
}

fn legacy_revision(
    document: &Value,
    sha256: &str,
    revision_id: ThreatModelRevisionId,
    created_at: String,
    scope: ScopeRef,
) -> ThreatModelRevisionMetadata {
    ThreatModelRevisionMetadata {
        revision_id,
        sha256: sha256.to_string(),
        created_at,
        parent_revision_id: None,
        source_revision_id: None,
        source: ThreatModelRevisionSource::LegacyImport,
        run_id: None,
        verification: verification_cache(document, sha256),
        scope: Some(scope),
    }
}

pub(super) fn reconcile_locked(root: &Path, manifest: &ThreatModelManifest) -> Result<()> {
    validate_manifest(root, manifest)?;
    ensure_activation_audit(root, manifest)?;
    recover_pending_mirror_commit(root, manifest)?;
    reconcile_mirror(root, manifest).map(|_| ())
}

pub(super) fn reconcile_for_activation(
    root: &Path,
    manifest: &ThreatModelManifest,
    action: MirrorAction,
) -> Result<Option<String>> {
    validate_manifest(root, manifest)?;
    ensure_activation_audit(root, manifest)?;
    let reconciled = recover_pending_mirror_commit(root, manifest)
        .and_then(|_| reconcile_mirror(root, manifest));
    match reconciled {
        Ok(()) => Ok(None),
        Err(error) if action == MirrorAction::Discard => discarded_mirror_sha(error).map(Some),
        Err(error) => Err(error),
    }
}

fn discarded_mirror_sha(error: anyhow::Error) -> Result<String> {
    match error.downcast_ref::<ThreatModelStoreError>() {
        Some(ThreatModelStoreError::DivergentMirror { mirror_sha256, .. })
        | Some(ThreatModelStoreError::UnadoptableMirror { mirror_sha256, .. }) => {
            Ok(mirror_sha256.clone())
        }
        None => Err(error),
    }
}

pub(super) fn reconcile_mirror(root: &Path, manifest: &ThreatModelManifest) -> Result<()> {
    let Some(active) = &manifest.active else {
        return Ok(());
    };
    match super::super::store::inspect_legacy_threat_model(root)? {
        super::super::store::LegacyMirrorInspection::Missing => write_active_mirror(root, manifest),
        super::super::store::LegacyMirrorInspection::Document(document) => {
            let mirror_sha256 = document_sha256(&document)?;
            if mirror_sha256 == active.sha256 {
                return Ok(());
            }
            Err(ThreatModelStoreError::DivergentMirror {
                mirror_sha256,
                active_sha256: active.sha256.clone(),
            }
            .into())
        }
        super::super::store::LegacyMirrorInspection::Unadoptable { sha256, reason } => {
            Err(ThreatModelStoreError::UnadoptableMirror {
                mirror_sha256: sha256,
                active_sha256: active.sha256.clone(),
                reason,
            }
            .into())
        }
    }
}

pub(super) fn write_active_mirror(root: &Path, manifest: &ThreatModelManifest) -> Result<()> {
    let Some(active) = &manifest.active else {
        return Ok(());
    };
    let document = read_object(root, &active.sha256)?;
    super::super::store::write_persistent_threat_model_unchecked(root, &document)
}
