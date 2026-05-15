use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunArtifactManifest {
    pub run_id: String,
    pub artifacts: Vec<RunArtifact>,
}

pub fn load_run_artifacts(target: impl AsRef<Path>, run_id: &str) -> Result<Vec<RunArtifact>> {
    Ok(load_manifest(target, run_id)?.artifacts)
}

pub(crate) fn record_run_artifact(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: &RunArtifact,
) -> Result<PathBuf> {
    let mut manifest = load_manifest(&target, run_id)?;
    upsert_artifact(&mut manifest.artifacts, artifact.clone());
    write_manifest(target, &manifest)
}

fn load_manifest(target: impl AsRef<Path>, run_id: &str) -> Result<RunArtifactManifest> {
    let path = manifest_path(&target, run_id);
    if !path.exists() {
        return Ok(RunArtifactManifest {
            run_id: run_id.to_string(),
            artifacts: Vec::new(),
        });
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("Could not parse {}", path.display()))
}

fn write_manifest(target: impl AsRef<Path>, manifest: &RunArtifactManifest) -> Result<PathBuf> {
    let path = manifest_path(target, &manifest.run_id);
    fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))?;
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(manifest)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

fn upsert_artifact(artifacts: &mut Vec<RunArtifact>, artifact: RunArtifact) {
    if let Some(existing) = artifacts.iter_mut().find(|item| item.path == artifact.path) {
        *existing = artifact;
    } else {
        artifacts.push(artifact);
    }
}

fn manifest_path(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    run_dir(target, run_id).join("artifacts.json")
}
