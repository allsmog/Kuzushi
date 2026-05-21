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
    let label = label.into();
    let kind = kind.into();
    let path = path.display().to_string();
    let artifact = RunArtifact::from_declared(&label, &path, Some(&kind))
        .context("run artifact path must not be empty")?;
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
