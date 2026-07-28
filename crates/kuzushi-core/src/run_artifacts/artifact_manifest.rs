use super::*;
use crate::artifact_contract::{
    canonical_run_artifact_spec, optional_run_artifact_spec, tool_input_artifact_spec,
    tool_result_artifact_spec, CanonicalRunArtifactSpec, CANONICAL_RUN_ARTIFACTS,
    OPTIONAL_RUN_ARTIFACTS, SCAN_PIPELINE_ARTIFACTS, TOOL_INPUT_ARTIFACTS, TOOL_RESULT_ARTIFACTS,
};
use crate::content_store::ObjectRef;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunArtifactManifest {
    pub run_id: String,
    pub artifacts: Vec<RunArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<RunArtifactObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunArtifactObject {
    pub label: String,
    pub path: String,
    pub object_ref: ObjectRef,
}

pub fn load_run_artifacts(target: impl AsRef<Path>, run_id: &str) -> Result<Vec<RunArtifact>> {
    Ok(load_manifest(target, run_id)?.artifacts)
}

pub(crate) fn record_canonical_run_artifacts(target: impl AsRef<Path>, run_id: &str) -> Result<()> {
    let target = target.as_ref();
    for artifact in canonical_run_artifacts() {
        record_run_artifact(target, run_id, &artifact)?;
    }
    Ok(())
}

pub(crate) fn record_run_artifact(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: &RunArtifact,
) -> Result<PathBuf> {
    let target = target.as_ref();
    let _guard = super::run_ledger::acquire_run_ledger_lock(target, run_id)?;
    let mut manifest = load_manifest(target, run_id)?;
    let artifact = artifact
        .normalized()
        .context("run artifact path must not be empty")?;
    validate_manifest_artifact_path(target, run_id, &artifact.path)?;
    let artifact = super::run_artifact::normalize_run_artifact_identity(target, run_id, &artifact)
        .context("run artifact path must not be empty")?;
    upsert_artifact(&mut manifest.artifacts, artifact);
    write_manifest(target, &manifest)
}

pub(crate) fn record_run_artifact_object_under_lock(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: &RunArtifact,
    object_ref: ObjectRef,
    _guard: &crate::file_lock::ExclusiveFileLock,
) -> Result<PathBuf> {
    let target = target.as_ref();
    let mut manifest = load_manifest(target, run_id)?;
    let artifact = artifact
        .normalized()
        .context("run artifact path must not be empty")?;
    validate_manifest_artifact_path(target, run_id, &artifact.path)?;
    let artifact = super::run_artifact::normalize_run_artifact_identity(target, run_id, &artifact)
        .context("run artifact path must not be empty")?;
    upsert_artifact(&mut manifest.artifacts, artifact.clone());
    upsert_artifact_object(
        &mut manifest.objects,
        RunArtifactObject {
            label: artifact.label,
            path: artifact.path,
            object_ref,
        },
    );
    write_manifest(target, &manifest)
}

fn load_manifest(target: impl AsRef<Path>, run_id: &str) -> Result<RunArtifactManifest> {
    let target = target.as_ref();
    let Some((path, text)) = read_manifest_text(target, run_id)? else {
        return Ok(empty_manifest(run_id));
    };
    let mut manifest = parse_manifest_body(&text, &path)?;
    if manifest.run_id != run_id {
        anyhow::bail!(
            "Artifact manifest runId does not match requested run id: {}",
            path.display()
        );
    }
    validate_manifest_artifact_paths(target, run_id, &manifest)?;
    normalize_manifest_identities(target, run_id, &mut manifest);
    Ok(manifest)
}

fn normalize_manifest_identities(target: &Path, run_id: &str, manifest: &mut RunArtifactManifest) {
    manifest.artifacts = super::run_artifact::normalize_run_artifact_identities(
        target,
        run_id,
        std::mem::take(&mut manifest.artifacts),
    );
    let mut objects = Vec::new();
    for mut object in std::mem::take(&mut manifest.objects) {
        object.path =
            super::run_artifact::normalize_run_artifact_path(target, run_id, &object.path);
        upsert_artifact_object(&mut objects, object);
    }
    manifest.objects = objects;
}

fn read_manifest_text(target: &Path, run_id: &str) -> Result<Option<(PathBuf, String)>> {
    let read = super::read_run_artifact_text(target, run_id, manifest_artifact_spec().leaf);
    if matches!(&read, super::RunArtifactRead::Missing { .. }) {
        return Ok(None);
    }
    read.require("Artifact manifest").map(Some)
}

fn validate_manifest_artifact_paths(
    target: &Path,
    run_id: &str,
    manifest: &RunArtifactManifest,
) -> Result<()> {
    for artifact in &manifest.artifacts {
        validate_manifest_artifact_path(target, run_id, &artifact.path)?;
    }
    for object in &manifest.objects {
        validate_manifest_artifact_path(target, run_id, &object.path)?;
    }
    validate_known_run_artifact_paths(target, run_id)?;
    Ok(())
}

fn validate_known_run_artifact_paths(target: &Path, run_id: &str) -> Result<()> {
    for spec in CANONICAL_RUN_ARTIFACTS
        .iter()
        .chain(OPTIONAL_RUN_ARTIFACTS.iter())
        .chain(TOOL_INPUT_ARTIFACTS.iter())
        .chain(TOOL_RESULT_ARTIFACTS.iter())
        .chain(SCAN_PIPELINE_ARTIFACTS.iter())
    {
        checked_run_artifact_path(target, run_id, spec.leaf)?;
    }
    Ok(())
}

fn validate_manifest_artifact_path(target: &Path, run_id: &str, value: &str) -> Result<()> {
    let path = Path::new(value);
    if !path.is_absolute() {
        ArtifactPath::parse(path)?;
        checked_run_artifact_path(target, run_id, path)?;
        return Ok(());
    }
    let root = fs::canonicalize(target)
        .with_context(|| format!("Could not resolve artifact target {}", target.display()))?;
    let relative = path
        .strip_prefix(target)
        .or_else(|_| path.strip_prefix(&root))
        .with_context(|| {
            format!(
                "run artifact path escapes target {}: {}",
                root.display(),
                path.display()
            )
        })?;
    let checked = crate::workspace::validated_workspace_descendant(&root, relative)?;
    let canonical = fs::canonicalize(&checked)
        .with_context(|| format!("Could not resolve run artifact {}", path.display()))?;
    canonical.strip_prefix(&root).with_context(|| {
        format!(
            "run artifact path escapes target {}: {}",
            root.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn parse_manifest_body(text: &str, path: &Path) -> Result<RunArtifactManifest> {
    let value: Value = serde_json::from_str(text)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    if !value.is_object() {
        anyhow::bail!("Artifact manifest is not a JSON object: {}", path.display());
    }
    require_manifest_run_id(&value, path)?;
    require_manifest_artifacts_array(&value, path)?;
    require_manifest_artifact_objects(&value, path)?;
    require_manifest_artifact_fields(&value, path)?;
    require_known_manifest_artifact_metadata(&value, path)?;
    serde_json::from_value(value).map_err(|error| {
        anyhow::anyhow!(
            "Artifact manifest is not canonical: {error}: {}",
            path.display()
        )
    })
}

fn require_manifest_run_id(value: &Value, path: &Path) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    let run_id = object.get("runId");
    if run_id.is_none() {
        anyhow::bail!("Artifact manifest is missing runId: {}", path.display());
    }
    require_manifest_run_id_value("runId", run_id, path)
}

fn require_manifest_run_id_value(field: &str, value: Option<&Value>, path: &Path) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    match value.as_str() {
        Some(text) if !text.trim().is_empty() => Ok(()),
        _ => anyhow::bail!(
            "Artifact manifest {field} is not a non-empty string: {}",
            path.display()
        ),
    }
}

fn require_manifest_artifacts_array(value: &Value, path: &Path) -> Result<()> {
    match value.get("artifacts") {
        Some(artifacts) if artifacts.is_array() => Ok(()),
        Some(_) => anyhow::bail!(
            "Artifact manifest artifacts is not a JSON array: {}",
            path.display()
        ),
        None => anyhow::bail!(
            "Artifact manifest is missing artifacts array: {}",
            path.display()
        ),
    }
}

fn require_manifest_artifact_objects(value: &Value, path: &Path) -> Result<()> {
    let Some(artifacts) = value.get("artifacts").and_then(Value::as_array) else {
        return Ok(());
    };
    if let Some(index) = artifacts.iter().position(|artifact| !artifact.is_object()) {
        anyhow::bail!(
            "Artifact manifest artifact at index {index} is not a JSON object: {}",
            path.display()
        );
    }
    Ok(())
}

fn require_manifest_artifact_fields(value: &Value, path: &Path) -> Result<()> {
    let Some(artifacts) = value.get("artifacts").and_then(Value::as_array) else {
        return Ok(());
    };
    for (index, artifact) in artifacts.iter().enumerate() {
        require_manifest_artifact_string(artifact, index, path, "label")?;
        require_manifest_artifact_string(artifact, index, path, "path")?;
        require_manifest_artifact_string(artifact, index, path, "kind")?;
    }
    Ok(())
}

fn require_manifest_artifact_string(
    artifact: &Value,
    index: usize,
    path: &Path,
    field: &str,
) -> Result<()> {
    let Some(value) = artifact.get(field) else {
        anyhow::bail!(
            "Artifact manifest artifact at index {index} is missing {field}: {}",
            path.display()
        );
    };
    match value.as_str() {
        Some(text) if !text.trim().is_empty() => Ok(()),
        _ => anyhow::bail!(
            "Artifact manifest artifact at index {index} {field} is not a non-empty string: {}",
            path.display()
        ),
    }
}

fn require_known_manifest_artifact_metadata(value: &Value, path: &Path) -> Result<()> {
    let Some(artifacts) = value.get("artifacts").and_then(Value::as_array) else {
        return Ok(());
    };
    for (index, artifact) in artifacts.iter().enumerate() {
        let Some(spec) = known_manifest_artifact_spec(artifact) else {
            continue;
        };
        require_manifest_artifact_spec_field(artifact, index, path, "label", spec.label)?;
        require_manifest_artifact_spec_field(artifact, index, path, "kind", spec.kind)?;
    }
    Ok(())
}

fn known_manifest_artifact_spec(artifact: &Value) -> Option<&'static CanonicalRunArtifactSpec> {
    let leaf = artifact
        .get("path")
        .and_then(Value::as_str)
        .and_then(manifest_artifact_leaf)?;
    canonical_run_artifact_spec(leaf)
        .or_else(|| optional_run_artifact_spec(leaf))
        .or_else(|| tool_input_artifact_spec(leaf))
        .or_else(|| tool_result_artifact_spec(leaf))
}

fn manifest_artifact_leaf(path: &str) -> Option<&str> {
    Path::new(path).file_name().and_then(|leaf| leaf.to_str())
}

fn require_manifest_artifact_spec_field(
    artifact: &Value,
    index: usize,
    path: &Path,
    field: &str,
    expected: &str,
) -> Result<()> {
    if artifact.get(field).and_then(Value::as_str) == Some(expected) {
        return Ok(());
    }
    anyhow::bail!(
        "Artifact manifest artifact at index {index} {field} does not match canonical artifact contract: {}",
        path.display()
    );
}

fn empty_manifest(run_id: &str) -> RunArtifactManifest {
    RunArtifactManifest {
        run_id: run_id.to_string(),
        artifacts: Vec::new(),
        objects: Vec::new(),
    }
}

fn write_manifest(target: impl AsRef<Path>, manifest: &RunArtifactManifest) -> Result<PathBuf> {
    ensure_run_artifact_parent(&target, &manifest.run_id, manifest_artifact_spec().leaf)?;
    let path = manifest_path(target, &manifest.run_id)?;
    let body = format!("{}\n", serde_json::to_string_pretty(manifest)?);
    crate::fs_atomic::write_atomic(&path, &body)
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

fn upsert_artifact_object(objects: &mut Vec<RunArtifactObject>, object: RunArtifactObject) {
    if let Some(existing) = objects.iter_mut().find(|item| item.path == object.path) {
        *existing = object;
    } else {
        objects.push(object);
    }
}

fn canonical_run_artifacts() -> Vec<RunArtifact> {
    CANONICAL_RUN_ARTIFACTS
        .iter()
        .map(CanonicalRunArtifactSpec::artifact)
        .collect()
}

impl CanonicalRunArtifactSpec {
    fn artifact(&self) -> RunArtifact {
        RunArtifact {
            label: self.label.to_string(),
            path: self.leaf.to_string(),
            kind: self.kind.to_string(),
        }
    }
}

fn manifest_path(target: impl AsRef<Path>, run_id: &str) -> Result<PathBuf> {
    checked_run_artifact_path(target, run_id, manifest_artifact_spec().leaf)
}

fn manifest_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("artifacts.json").expect("artifact manifest must be in shared spec")
}
