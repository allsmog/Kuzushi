use super::*;

const MIRROR_COMMIT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingMirrorCommit {
    schema_version: u32,
    manifest_generation: u64,
    active: ThreatModelRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous: Option<ThreatModelRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mirror_before_sha256: Option<String>,
}

pub(super) fn begin_mirror_commit(root: &Path, manifest: &ThreatModelManifest) -> Result<()> {
    let activation = matching_activation(manifest)?;
    let mirror_before_sha256 = inspect_mirror_sha256(root)?;
    ensure_authorized_mirror(activation, mirror_before_sha256.as_deref())?;
    let pending = PendingMirrorCommit {
        schema_version: MIRROR_COMMIT_SCHEMA_VERSION,
        manifest_generation: manifest.generation,
        active: activation.model_ref.clone(),
        previous: activation.previous.clone(),
        mirror_before_sha256,
    };
    write_pending_mirror_commit(root, &pending)?;
    ensure_mirror_unchanged(root, &pending)?;
    withdraw_mirror(root)
}

pub(super) fn recover_pending_mirror_commit(
    root: &Path,
    manifest: &ThreatModelManifest,
) -> Result<()> {
    let Some(pending) = read_pending_mirror_commit(root)? else {
        return Ok(());
    };
    validate_pending_state(manifest, &pending)?;
    reconcile_mirror(root, manifest)?;
    sync_mirror_parent(root)?;
    clear_pending_mirror_commit(root)
}

fn matching_activation(manifest: &ThreatModelManifest) -> Result<&ThreatModelActivation> {
    let activation = manifest
        .last_activation
        .as_ref()
        .context("active threat-model update has no activation checkpoint")?;
    anyhow::ensure!(
        activation.manifest_generation == manifest.generation
            && manifest.active.as_ref() == Some(&activation.model_ref),
        "active threat-model update has an inconsistent activation checkpoint"
    );
    Ok(activation)
}

fn ensure_authorized_mirror(
    activation: &ThreatModelActivation,
    mirror_sha256: Option<&str>,
) -> Result<()> {
    let Some(mirror_sha256) = mirror_sha256 else {
        return Ok(());
    };
    let authorized = activation.model_ref.sha256 == mirror_sha256
        || activation
            .previous
            .as_ref()
            .is_some_and(|previous| previous.sha256 == mirror_sha256)
        || activation.discarded_mirror_sha256.as_deref() == Some(mirror_sha256);
    anyhow::ensure!(authorized, "compatibility mirror changed before commit");
    Ok(())
}

fn validate_pending_state(
    manifest: &ThreatModelManifest,
    pending: &PendingMirrorCommit,
) -> Result<()> {
    anyhow::ensure!(
        pending.schema_version == MIRROR_COMMIT_SCHEMA_VERSION,
        "unsupported threat-model mirror commit schemaVersion {}",
        pending.schema_version
    );
    let committed = pending.manifest_generation == manifest.generation
        && manifest.active.as_ref() == Some(&pending.active);
    let uncommitted = pending.manifest_generation == manifest.generation.saturating_add(1)
        && pending.previous.as_ref() == manifest.active.as_ref();
    anyhow::ensure!(
        committed || uncommitted,
        "threat-model mirror commit does not match the authoritative manifest"
    );
    Ok(())
}

fn ensure_mirror_unchanged(root: &Path, pending: &PendingMirrorCommit) -> Result<()> {
    anyhow::ensure!(
        inspect_mirror_sha256(root)? == pending.mirror_before_sha256,
        "compatibility mirror changed while the model-store commit was prepared"
    );
    Ok(())
}

fn inspect_mirror_sha256(root: &Path) -> Result<Option<String>> {
    match super::super::store::inspect_legacy_threat_model(root)? {
        super::super::store::LegacyMirrorInspection::Missing => Ok(None),
        super::super::store::LegacyMirrorInspection::Document(document) => {
            document_sha256(&document).map(Some)
        }
        super::super::store::LegacyMirrorInspection::Unadoptable { sha256, .. } => Ok(Some(sha256)),
    }
}

fn write_pending_mirror_commit(root: &Path, pending: &PendingMirrorCommit) -> Result<()> {
    let mut body = serde_json::to_vec_pretty(pending)?;
    body.push(b'\n');
    crate::fs_atomic::write_atomic_bytes(&pending_mirror_commit_path(root), &body)
}

fn read_pending_mirror_commit(root: &Path) -> Result<Option<PendingMirrorCommit>> {
    let path = pending_mirror_commit_path(root);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            let body = crate::bounded_file::read_utf8_text_within(root, &path, MAX_STORE_JSON_BYTES)?;
            serde_json::from_str(&body)
                .with_context(|| format!("Threat-model mirror commit {} is malformed", path.display()))
                .map(Some)
        }
        Ok(_) => anyhow::bail!("Threat-model mirror commit {} is not a regular file", path.display()),
    }
}

fn withdraw_mirror(root: &Path) -> Result<()> {
    let path = super::super::store::persistent_threat_model_path(root);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(&path)?;
            crate::fs_atomic::sync_parent_dir(&path).map_err(Into::into)
        }
        Ok(_) => anyhow::bail!("Threat-model mirror {} is not a regular file", path.display()),
    }
}

fn clear_pending_mirror_commit(root: &Path) -> Result<()> {
    let path = pending_mirror_commit_path(root);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(&path)?;
            crate::fs_atomic::sync_parent_dir(&path).map_err(Into::into)
        }
        Ok(_) => anyhow::bail!("Threat-model mirror commit {} is not a regular file", path.display()),
    }
}

fn sync_mirror_parent(root: &Path) -> Result<()> {
    let path = super::super::store::persistent_threat_model_path(root);
    crate::fs_atomic::sync_parent_dir(&path).map_err(Into::into)
}

pub(super) fn pending_mirror_commit_path(root: &Path) -> PathBuf {
    threat_model_store_path(root).join(MIRROR_COMMIT_FILE)
}
