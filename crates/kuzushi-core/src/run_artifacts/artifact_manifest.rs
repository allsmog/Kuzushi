use super::*;
use crate::artifact_contract::{CanonicalRunArtifactSpec, CANONICAL_RUN_ARTIFACTS};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunArtifactManifest {
    #[serde(alias = "run_id")]
    pub run_id: String,
    pub artifacts: Vec<RunArtifact>,
}

pub fn load_run_artifacts(target: impl AsRef<Path>, run_id: &str) -> Result<Vec<RunArtifact>> {
    Ok(normalized_artifacts(load_manifest(target, run_id)?.artifacts))
}

pub(crate) fn record_canonical_run_artifacts(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<()> {
    let target = target.as_ref();
    for artifact in canonical_run_artifacts(target, run_id) {
        record_run_artifact(target, run_id, &artifact)?;
    }
    Ok(())
}

pub(crate) fn record_run_artifact(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: &RunArtifact,
) -> Result<PathBuf> {
    let mut manifest = load_manifest(&target, run_id)?;
    let artifact = artifact
        .normalized()
        .context("run artifact path must not be empty")?;
    upsert_artifact(&mut manifest.artifacts, artifact);
    write_manifest(target, &manifest)
}

fn load_manifest(target: impl AsRef<Path>, run_id: &str) -> Result<RunArtifactManifest> {
    let path = manifest_path(&target, run_id);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(empty_manifest(run_id)),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not inspect {}", path.display()));
        }
    };
    if !metadata.is_file() {
        anyhow::bail!("Artifact manifest is not a file: {}", path.display());
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("Could not parse {}", path.display()))
}

fn empty_manifest(run_id: &str) -> RunArtifactManifest {
    RunArtifactManifest {
        run_id: run_id.to_string(),
        artifacts: Vec::new(),
    }
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

fn canonical_run_artifacts(target: &Path, run_id: &str) -> Vec<RunArtifact> {
    CANONICAL_RUN_ARTIFACTS
        .iter()
        .map(|spec| spec.artifact(target, run_id))
        .collect()
}

fn normalized_artifacts(artifacts: Vec<RunArtifact>) -> Vec<RunArtifact> {
    artifacts
        .into_iter()
        .filter_map(|artifact| artifact.normalized())
        .collect()
}

impl CanonicalRunArtifactSpec {
    fn artifact(&self, target: &Path, run_id: &str) -> RunArtifact {
        RunArtifact {
            label: self.label.to_string(),
            path: run_dir(target, run_id).join(self.leaf).display().to_string(),
            kind: self.kind.to_string(),
        }
    }
}

fn manifest_path(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    run_dir(target, run_id).join("artifacts.json")
}
