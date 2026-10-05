use super::*;

pub(super) fn read_manifest(root: &Path) -> Result<Option<ThreatModelManifest>> {
    let path = threat_model_manifest_path(root);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            let body =
                crate::bounded_file::read_utf8_text_within(root, &path, MAX_STORE_JSON_BYTES)?;
            serde_json::from_str(&body)
                .with_context(|| format!("Threat-model manifest {} is malformed", path.display()))
                .map(Some)
        }
        Ok(_) => anyhow::bail!(
            "Threat-model manifest {} is not a regular file",
            path.display()
        ),
    }
}

pub(super) fn validate_manifest(root: &Path, manifest: &ThreatModelManifest) -> Result<()> {
    anyhow::ensure!(
        manifest.schema_version == STORE_SCHEMA_VERSION,
        "unsupported threat-model manifest schemaVersion {}; expected {}",
        manifest.schema_version,
        STORE_SCHEMA_VERSION
    );
    validate_manifest_models(manifest)?;
    if let Some(active) = &manifest.active {
        validate_ref_in_manifest(manifest, active)?;
        read_object(root, &active.sha256)?;
    }
    Ok(())
}

pub(super) fn validate_manifest_models(manifest: &ThreatModelManifest) -> Result<()> {
    let mut models = BTreeSet::new();
    let mut revisions = BTreeSet::new();
    for model in &manifest.models {
        validate_typed_id(model.model_id.as_str(), "tm_")?;
        anyhow::ensure!(
            models.insert(model.model_id.clone()),
            "duplicate threat-model id"
        );
        anyhow::ensure!(
            !model.revisions.is_empty(),
            "threat-model lineage has no revisions"
        );
        anyhow::ensure!(
            model
                .revisions
                .iter()
                .any(|row| row.revision_id == model.head_revision),
            "threat-model head revision is absent from its lineage"
        );
        for revision in &model.revisions {
            validate_typed_id(revision.revision_id.as_str(), "tmr_")?;
            validate_sha256(&revision.sha256)?;
            anyhow::ensure!(
                revisions.insert(revision.revision_id.clone()),
                "duplicate revision id"
            );
        }
    }
    Ok(())
}

pub(super) fn validate_ref_in_manifest(
    manifest: &ThreatModelManifest,
    model_ref: &ThreatModelRef,
) -> Result<()> {
    validate_sha256(&model_ref.sha256)?;
    let model = manifest
        .models
        .iter()
        .find(|model| model.model_id == model_ref.model_id)
        .context("active threat-model lineage is absent from manifest")?;
    let revision = model
        .revisions
        .iter()
        .find(|revision| revision.revision_id == model_ref.revision_id)
        .context("active threat-model revision is absent from manifest")?;
    anyhow::ensure!(
        revision.sha256 == model_ref.sha256,
        "active threat-model SHA disagrees with revision metadata"
    );
    Ok(())
}

pub(in crate::capabilities::threat_model::persistence) fn validate_sha256(value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .context("threat-model digest must start with sha256:")?;
    anyhow::ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "threat-model digest must contain 64 lowercase hexadecimal characters"
    );
    Ok(())
}

pub(super) struct StoredObject {
    pub(super) sha256: String,
}

pub(super) fn write_object(root: &Path, document: &Value) -> Result<StoredObject> {
    let bytes = crate::review_yield::domain::canonical_json_bytes(document)?;
    let sha256 = crate::run_lifecycle::sha256_content_digest(&bytes);
    let path = object_path(root, &sha256)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            let existing =
                crate::bounded_file::read_regular_bytes_within(root, &path, MAX_STORE_JSON_BYTES)?;
            anyhow::ensure!(
                existing == bytes,
                "immutable threat-model object {} is corrupt",
                path.display()
            );
        }
        Ok(_) => anyhow::bail!(
            "immutable threat-model object {} is not a regular file",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            crate::fs_atomic::write_atomic_bytes(&path, &bytes)?;
        }
        Err(error) => {
            return Err(error).with_context(|| format!("Could not inspect {}", path.display()))
        }
    }
    Ok(StoredObject { sha256 })
}

pub(super) fn read_object(root: &Path, sha256: &str) -> Result<Value> {
    let path = object_path(root, sha256)?;
    let bytes = crate::bounded_file::read_regular_bytes_within(root, &path, MAX_STORE_JSON_BYTES)
        .with_context(|| {
        format!(
            "Could not read active threat-model object {}",
            path.display()
        )
    })?;
    anyhow::ensure!(
        crate::run_lifecycle::sha256_content_digest(&bytes) == sha256,
        "active threat-model object {} failed SHA verification",
        path.display()
    );
    serde_json::from_slice(&bytes)
        .with_context(|| format!("Active threat-model object {} is malformed", path.display()))
}

pub(super) fn object_path(root: &Path, sha256: &str) -> Result<PathBuf> {
    validate_sha256(sha256)?;
    let digest = sha256.trim_start_matches("sha256:");
    Ok(threat_model_store_path(root)
        .join(OBJECTS_DIR)
        .join(format!("sha256-{digest}.json")))
}

pub(super) fn prepare_store_directories(root: &Path) -> Result<()> {
    crate::workspace::ensure_workspace_descendant_dir(
        root,
        Path::new(crate::workspace::KUZUSHI_STATE_DIR)
            .join(STORE_DIR)
            .join(OBJECTS_DIR),
    )?;
    Ok(())
}

pub(super) fn acquire_store_lock(root: &Path) -> Result<crate::file_lock::ExclusiveFileLock> {
    crate::file_lock::ExclusiveFileLock::acquire(&threat_model_store_path(root).join(STORE_LOCK))
}

pub(super) fn acquire_store_read_lock(root: &Path) -> Result<crate::file_lock::SharedFileLock> {
    crate::file_lock::SharedFileLock::acquire(&threat_model_store_path(root).join(STORE_LOCK))
}
