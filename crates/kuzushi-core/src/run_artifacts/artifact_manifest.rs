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

fn canonical_run_artifacts(target: &Path, run_id: &str) -> Vec<RunArtifact> {
    CANONICAL_RUN_ARTIFACTS
        .iter()
        .map(|spec| spec.artifact(target, run_id))
        .collect()
}

struct CanonicalRunArtifactSpec {
    leaf: &'static str,
    label: &'static str,
    kind: &'static str,
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

const CANONICAL_RUN_ARTIFACTS: &[CanonicalRunArtifactSpec] = &[
    CanonicalRunArtifactSpec {
        leaf: "run.json",
        label: "run metadata",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "events.jsonl",
        label: "run events",
        kind: "jsonl",
    },
    CanonicalRunArtifactSpec {
        leaf: "trace.jsonl",
        label: "runtime trace",
        kind: "jsonl",
    },
    CanonicalRunArtifactSpec {
        leaf: "context.json",
        label: "context snapshot",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "attack-surface.json",
        label: "attack surface",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "threat-model.json",
        label: "threat model",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "recommendations.json",
        label: "recommendations",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "findings.json",
        label: "findings",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "proof.json",
        label: "proof",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "failures.json",
        label: "failure handoff",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "report.md",
        label: "report",
        kind: "markdown",
    },
    CanonicalRunArtifactSpec {
        leaf: "artifacts.json",
        label: "artifact manifest",
        kind: "json",
    },
];

fn manifest_path(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    run_dir(target, run_id).join("artifacts.json")
}
