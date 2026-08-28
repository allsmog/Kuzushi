use super::*;

pub(super) fn commit_manifest_update(
    root: &Path,
    mut manifest: ThreatModelManifest,
    active: Option<ThreatModelRef>,
    actor: &str,
    source: ActivationSource,
    discarded_mirror_sha256: Option<String>,
) -> Result<()> {
    let previous = manifest.active.clone();
    manifest.generation = manifest.generation.saturating_add(1);
    let updates_active = active.is_some();
    if let Some(active) = active {
        manifest.active = Some(active.clone());
        manifest.last_activation = Some(new_activation(
            manifest.generation,
            active,
            previous,
            actor,
            source,
            discarded_mirror_sha256,
        ));
    }
    if updates_active {
        begin_mirror_commit(root, &manifest)?;
    }
    write_manifest(root, &manifest)?;
    ensure_activation_audit(root, &manifest)?;
    if updates_active {
        recover_pending_mirror_commit(root, &manifest)
    } else {
        Ok(())
    }
}

pub(super) fn new_activation(
    generation: u64,
    model_ref: ThreatModelRef,
    previous: Option<ThreatModelRef>,
    actor: &str,
    source: ActivationSource,
    discarded_mirror_sha256: Option<String>,
) -> ThreatModelActivation {
    ThreatModelActivation {
        event_id: format!("tma_{}", Uuid::new_v4().simple()),
        manifest_generation: generation,
        activated_at: now_string(),
        model_ref,
        previous,
        actor: actor.to_string(),
        source,
        discarded_mirror_sha256,
    }
}

pub(super) fn write_manifest(root: &Path, manifest: &ThreatModelManifest) -> Result<()> {
    validate_manifest(root, manifest)?;
    let mut body = serde_json::to_vec_pretty(manifest)?;
    body.push(b'\n');
    crate::fs_atomic::write_atomic_bytes(&threat_model_manifest_path(root), &body)
}

pub(super) fn ensure_activation_audit(root: &Path, manifest: &ThreatModelManifest) -> Result<()> {
    let Some(activation) = &manifest.last_activation else {
        return Ok(());
    };
    let path = threat_model_store_path(root).join(ACTIVATIONS_FILE);
    crate::jsonl_tail::heal_torn_jsonl_tail_at(
        &path,
        MAX_ACTIVATION_LINE_BYTES,
        "Threat-model activation ledger",
    )?;
    if activation_log_contains(root, &path, &activation.event_id)? {
        return Ok(());
    }
    append_activation(&path, activation)
}

pub(super) fn activation_log_contains(root: &Path, path: &Path, event_id: &str) -> Result<bool> {
    let body = match crate::bounded_file::read_utf8_text_within(
        root,
        path,
        MAX_ACTIVATION_LOG_BYTES as usize,
    ) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not read {}", path.display()))
        }
    };
    for (index, line) in body.lines().enumerate() {
        let activation =
            serde_json::from_str::<ThreatModelActivation>(line).with_context(|| {
                format!(
                    "Threat-model activation ledger {} has malformed event {}",
                    path.display(),
                    index + 1
                )
            })?;
        if activation.event_id == event_id {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn append_activation(path: &Path, activation: &ThreatModelActivation) -> Result<()> {
    let mut line = serde_json::to_vec(activation)?;
    line.push(b'\n');
    anyhow::ensure!(
        line.len() <= MAX_ACTIVATION_LINE_BYTES,
        "threat-model activation event is too large"
    );
    let existing = fs::symlink_metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    anyhow::ensure!(
        existing.saturating_add(line.len() as u64) <= MAX_ACTIVATION_LOG_BYTES,
        "threat-model activation ledger is too large"
    );
    let mut file = open_activation_append(path)?;
    file.write_all(&line)?;
    file.sync_all()?;
    crate::fs_atomic::sync_parent_dir(path)?;
    Ok(())
}

#[cfg(unix)]
pub(super) fn open_activation_append(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
pub(super) fn open_activation_append(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().create(true).append(true).open(path)
}
