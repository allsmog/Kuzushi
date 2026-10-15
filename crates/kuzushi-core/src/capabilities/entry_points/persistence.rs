use super::domain::*;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub(super) fn entry_points_path(target: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(ENTRY_POINTS_FILE)
}

pub(super) fn read_context_snapshot(target: &Path) -> Result<Option<ContextSnapshotDocument>> {
    let path = crate::context::context_snapshot_path(target);
    if !path_present(&path)? {
        return Ok(None);
    }
    let raw = crate::bounded_file::read_utf8_text_within(
        target,
        &path,
        crate::context::MAX_CONTEXT_SNAPSHOT_BYTES,
    )
    .with_context(|| format!("Could not read context snapshot from {}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .with_context(|| format!("context snapshot at {} is not valid JSON", path.display()))?;
    let identity = context_snapshot_identity(&value, &raw)?;
    Ok(Some(ContextSnapshotDocument { value, identity }))
}

pub(super) fn context_snapshot_identity(
    value: &Value,
    raw: &str,
) -> Result<ContextSnapshotIdentity> {
    context_snapshot_identity_with_sha(value, crate::options::prompt_content_sha256(raw))
}

pub(super) fn context_snapshot_identity_with_sha(
    value: &Value,
    sha256: String,
) -> Result<ContextSnapshotIdentity> {
    let target = required_text(value, "/target", "target")?.to_string();
    let timestamp = value
        .pointer("/timestamp")
        .and_then(Value::as_u64)
        .context("context snapshot has no numeric timestamp")?;
    Ok(ContextSnapshotIdentity {
        target,
        timestamp,
        sha256,
        revision: optional_text(value, "/provenance/revision"),
        revision_dirty: value
            .pointer("/provenance/revisionDirty")
            .and_then(Value::as_bool),
        tree_hash: optional_text(value, "/provenance/treeHash"),
    })
}

fn required_text<'a>(value: &'a Value, pointer: &str, label: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .with_context(|| format!("context snapshot has no {label}"))
}

fn optional_text(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .map(str::to_string)
}

pub(super) fn read_entry_point_catalog(target: &Path) -> Result<Option<EntryPointCatalog>> {
    let path = entry_points_path(target);
    if !path_present(&path)? {
        return Ok(None);
    }
    let raw = crate::bounded_file::read_utf8_text_within(target, &path, MAX_ENTRY_POINTS_BYTES)
        .with_context(|| format!("Could not read entry-point catalog from {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| {
            format!(
                "entry-point catalog at {} is not valid JSON",
                path.display()
            )
        })
        .map(Some)
}

#[cfg(test)]
pub(super) fn write_entry_point_catalog(
    target: &Path,
    catalog: &EntryPointCatalog,
) -> Result<PathBuf> {
    write_entry_point_catalog_after_validation(target, catalog, || Ok(()))
}

pub(super) fn write_entry_point_catalog_after_validation(
    target: &Path,
    catalog: &EntryPointCatalog,
    validate_before_publish: impl FnOnce() -> Result<()>,
) -> Result<PathBuf> {
    let body = serde_json::to_vec_pretty(catalog).context("serializing entry-points artifact")?;
    anyhow::ensure!(
        body.len() <= MAX_ENTRY_POINTS_BYTES,
        "entry-points artifact is {} bytes, above the {}-byte read/write limit",
        body.len(),
        MAX_ENTRY_POINTS_BYTES
    );
    validate_before_publish()?;
    crate::workspace::write_workspace_state_file(
        target,
        Path::new(crate::workspace::KUZUSHI_STATE_DIR).join(ENTRY_POINTS_FILE),
        &body,
    )
}

fn path_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}
