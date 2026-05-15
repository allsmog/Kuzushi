use super::artifact_manifest::record_run_artifact;
use super::*;

pub(crate) fn write_run_artifact_text(
    target: impl AsRef<Path>,
    run_id: &str,
    leaf: &str,
    label: impl Into<String>,
    kind: impl Into<String>,
    body: &str,
) -> Result<RunArtifact> {
    let dir = run_dir(&target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    let path = dir.join(leaf);
    fs::write(&path, body_with_trailing_newline(body))
        .with_context(|| format!("Could not write {}", path.display()))?;
    let artifact = RunArtifact {
        label: label.into(),
        path: path.display().to_string(),
        kind: kind.into(),
    };
    record_run_artifact(target, run_id, &artifact)?;
    Ok(artifact)
}

fn body_with_trailing_newline(body: &str) -> String {
    if body.ends_with('\n') {
        body.to_string()
    } else {
        format!("{body}\n")
    }
}
