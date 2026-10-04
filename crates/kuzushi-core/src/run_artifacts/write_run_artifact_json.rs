use super::artifact_manifest::record_run_artifact_object_under_lock;
use super::*;
use crate::content_store::{ContentStore, ObjectKind};
use crate::workspace::workspace_objects_dir;

pub fn write_run_artifact_json(
    target: impl AsRef<Path>,
    run_id: &str,
    leaf: &str,
    label: impl Into<String>,
    value: &Value,
) -> Result<RunArtifact> {
    let target = target.as_ref();
    ensure_run_artifact_parent(target, run_id, leaf)?;
    let path = checked_run_artifact_path(target, run_id, leaf)?;
    let body = format!("{}\n", serde_json::to_string_pretty(value)?);
    publish_json(target, run_id, leaf, &path, label.into(), body.as_bytes())
}

pub(crate) fn write_run_artifact_json_bounded(
    target: &Path,
    run_id: &str,
    leaf: &str,
    label: &str,
    value: &Value,
    max_bytes: usize,
) -> Result<RunArtifact> {
    ensure_run_artifact_parent(target, run_id, leaf)?;
    let path = checked_run_artifact_path(target, run_id, leaf)?;
    let mut body = crate::checkpoint_limits::encode(value, max_bytes.saturating_sub(1))?;
    body.push(b'\n');
    publish_json(target, run_id, leaf, &path, label.into(), &body)
}

fn publish_json(
    target: &Path,
    run_id: &str,
    leaf: &str,
    path: &Path,
    label: String,
    body: &[u8],
) -> Result<RunArtifact> {
    let declared_path = path.display().to_string();
    let artifact = RunArtifact::from_declared(&label, &declared_path, Some("json"))
        .context("run artifact path must not be empty")?;
    let object_ref = ContentStore::open(workspace_objects_dir(target))?
        .put_bytes(json_artifact_object_kind(leaf), body)?;
    let guard = super::run_ledger::acquire_run_ledger_lock(target, run_id)?;
    crate::fs_atomic::write_atomic_bytes(path, body)
        .with_context(|| format!("Could not write {}", path.display()))?;
    record_run_artifact_object_under_lock(target, run_id, &artifact, object_ref, &guard)?;
    Ok(artifact)
}

fn json_artifact_object_kind(leaf: &str) -> ObjectKind {
    match leaf {
        "context.json" => ObjectKind::ContextSnapshot,
        "attack-surface.json" => ObjectKind::AttackSurfaceSnapshot,
        "findings.json" => ObjectKind::FindingObservationBatch,
        "proof.json" => ObjectKind::ProofSnapshot,
        "failures.json" => ObjectKind::DiagnosticBundle,
        _ => ObjectKind::Blob,
    }
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
