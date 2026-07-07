use super::artifact_manifest::{record_run_artifact, record_run_artifact_object};
use super::*;
use crate::content_store::{ContentStore, ObjectKind};
use crate::workspace::workspace_objects_dir;

pub(crate) fn write_run_artifact_text(
    target: impl AsRef<Path>,
    run_id: &str,
    leaf: &str,
    label: impl Into<String>,
    kind: impl Into<String>,
    body: &str,
) -> Result<RunArtifact> {
    let target = target.as_ref();
    let dir = run_dir(target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join(leaf);
    let body = body_with_trailing_newline(body);
    crate::fs_atomic::write_atomic(&path, &body)
        .with_context(|| format!("Could not write {}", path.display()))?;
    let label = label.into();
    let kind = kind.into();
    let path = path.display().to_string();
    let artifact = RunArtifact::from_declared(&label, &path, Some(&kind))
        .context("run artifact path must not be empty")?;
    record_run_artifact(target, run_id, &artifact)?;
    let object_ref = ContentStore::open(workspace_objects_dir(target))?
        .put_bytes(text_artifact_object_kind(leaf), body.as_bytes())?;
    record_run_artifact_object(target, run_id, &artifact, object_ref)?;
    Ok(artifact)
}

fn text_artifact_object_kind(leaf: &str) -> ObjectKind {
    match leaf {
        "report.md" => ObjectKind::ReportMarkdown,
        "report.sarif" => ObjectKind::ReportSarif,
        _ => ObjectKind::Blob,
    }
}

fn body_with_trailing_newline(body: &str) -> String {
    if body.ends_with('\n') {
        body.to_string()
    } else {
        format!("{body}\n")
    }
}
