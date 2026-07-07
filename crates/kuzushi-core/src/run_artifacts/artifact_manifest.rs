use super::*;
use crate::artifact_contract::{
    canonical_run_artifact_spec, optional_run_artifact_spec, tool_input_artifact_spec,
    tool_result_artifact_spec, CanonicalRunArtifactSpec, ARTIFACT_KIND_KEYS, ARTIFACT_LABEL_KEYS,
    ARTIFACT_PATH_KEYS, CANONICAL_RUN_ARTIFACTS,
};
use crate::content_store::ObjectRef;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunArtifactManifest {
    #[serde(alias = "run_id")]
    pub run_id: String,
    pub artifacts: Vec<RunArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<RunArtifactObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RunArtifactObject {
    pub label: String,
    pub path: String,
    pub object_ref: ObjectRef,
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

pub(crate) fn record_run_artifact_object(
    target: impl AsRef<Path>,
    run_id: &str,
    artifact: &RunArtifact,
    object_ref: ObjectRef,
) -> Result<PathBuf> {
    let mut manifest = load_manifest(&target, run_id)?;
    let artifact = artifact
        .normalized()
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
    let manifest = parse_manifest_body(&text, &path)?;
    if manifest.run_id != run_id {
        anyhow::bail!(
            "Artifact manifest runId does not match requested run id: {}",
            path.display()
        );
    }
    Ok(manifest)
}

fn parse_manifest_body(text: &str, path: &Path) -> Result<RunArtifactManifest> {
    let mut value: Value =
        serde_json::from_str(text).with_context(|| format!("Could not parse {}", path.display()))?;
    if !value.is_object() {
        anyhow::bail!("Artifact manifest is not a JSON object: {}", path.display());
    }
    require_manifest_run_id(&value, path)?;
    normalize_manifest_run_id_alias(&mut value, path)?;
    require_manifest_artifacts_array(&value, path)?;
    require_manifest_artifact_objects(&value, path)?;
    normalize_manifest_artifact_aliases(&mut value, path)?;
    require_known_manifest_artifact_metadata(&value, path)?;
    serde_json::from_value(value).with_context(|| format!("Could not parse {}", path.display()))
}

fn require_manifest_run_id(value: &Value, path: &Path) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    let run_id = object.get("runId");
    let snake_run_id = object.get("run_id");
    if run_id.is_none() && snake_run_id.is_none() {
        anyhow::bail!("Artifact manifest is missing runId: {}", path.display());
    }
    require_manifest_run_id_value("runId", run_id, path)?;
    require_manifest_run_id_value("run_id", snake_run_id, path)
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

fn normalize_manifest_run_id_alias(value: &mut Value, path: &Path) -> Result<()> {
    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };
    let Some(run_id) = object.get("runId") else {
        return Ok(());
    };
    let Some(snake_run_id) = object.get("run_id") else {
        return Ok(());
    };
    if run_id != snake_run_id {
        anyhow::bail!(
            "Artifact manifest runId and run_id disagree: {}",
            path.display()
        );
    }
    object.remove("run_id");
    Ok(())
}

fn require_manifest_artifacts_array(value: &Value, path: &Path) -> Result<()> {
    match value.get("artifacts") {
        Some(artifacts) if artifacts.is_array() => Ok(()),
        Some(_) => anyhow::bail!(
            "Artifact manifest artifacts is not a JSON array: {}",
            path.display()
        ),
        None => anyhow::bail!("Artifact manifest is missing artifacts array: {}", path.display()),
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

fn normalize_manifest_artifact_aliases(value: &mut Value, path: &Path) -> Result<()> {
    let Some(artifacts) = value.get_mut("artifacts").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    for (index, artifact) in artifacts.iter_mut().enumerate() {
        let Some(object) = artifact.as_object_mut() else {
            continue;
        };
        normalize_manifest_artifact_alias_set(
            object,
            index,
            path,
            &ARTIFACT_LABEL_KEYS,
            "label",
            true,
            normalize_manifest_label_alias,
        )?;
        normalize_manifest_artifact_alias_set(
            object,
            index,
            path,
            &ARTIFACT_PATH_KEYS,
            "path",
            true,
            normalize_manifest_path_alias,
        )?;
        normalize_manifest_artifact_alias_set(
            object,
            index,
            path,
            &ARTIFACT_KIND_KEYS,
            "kind",
            true,
            normalize_manifest_kind_alias,
        )?;
    }
    Ok(())
}

fn normalize_manifest_artifact_alias_set(
    object: &mut Map<String, Value>,
    index: usize,
    path: &Path,
    keys: &[&str],
    field: &str,
    reject_empty: bool,
    normalize: fn(&str) -> String,
) -> Result<()> {
    let values = manifest_alias_values(object, index, path, keys, normalize)?;
    ensure_manifest_alias_present(&values, index, path, field)?;
    ensure_manifest_aliases_agree(&values, index, path, field)?;
    ensure_manifest_alias_non_empty(&values, index, path, field, reject_empty)?;
    insert_manifest_canonical_alias(object, keys[0], values.first());
    remove_manifest_aliases(object, &keys[1..]);
    Ok(())
}

struct ManifestAliasValue {
    raw: String,
    normalized: String,
}

fn manifest_alias_values(
    object: &Map<String, Value>,
    index: usize,
    path: &Path,
    keys: &[&str],
    normalize: fn(&str) -> String,
) -> Result<Vec<ManifestAliasValue>> {
    keys.iter()
        .filter_map(|key| {
            object
                .get(*key)
                .map(|value| manifest_alias_value(index, path, key, value, normalize))
        })
        .collect()
}

fn manifest_alias_value(
    index: usize,
    path: &Path,
    key: &str,
    value: &Value,
    normalize: fn(&str) -> String,
) -> Result<ManifestAliasValue> {
    let Some(raw) = value.as_str() else {
        anyhow::bail!(
            "Artifact manifest artifact at index {index} {key} is not a string: {}",
            path.display()
        );
    };
    Ok(ManifestAliasValue {
        raw: raw.to_string(),
        normalized: normalize(raw),
    })
}

fn ensure_manifest_alias_present(
    values: &[ManifestAliasValue],
    index: usize,
    path: &Path,
    field: &str,
) -> Result<()> {
    if values.is_empty() {
        anyhow::bail!(
            "Artifact manifest artifact at index {index} is missing {field} alias: {}",
            path.display()
        );
    }
    Ok(())
}

fn ensure_manifest_aliases_agree(
    values: &[ManifestAliasValue],
    index: usize,
    path: &Path,
    field: &str,
) -> Result<()> {
    let Some(first) = values.first() else {
        return Ok(());
    };
    if values
        .iter()
        .any(|value| value.normalized != first.normalized)
    {
        anyhow::bail!(
            "Artifact manifest artifact at index {index} has conflicting {field} aliases: {}",
            path.display()
        );
    }
    Ok(())
}

fn ensure_manifest_alias_non_empty(
    values: &[ManifestAliasValue],
    index: usize,
    path: &Path,
    field: &str,
    reject_empty: bool,
) -> Result<()> {
    if reject_empty && values.first().is_some_and(|value| value.normalized.is_empty()) {
        anyhow::bail!(
            "Artifact manifest artifact at index {index} {field} alias is empty: {}",
            path.display()
        );
    }
    Ok(())
}

fn insert_manifest_canonical_alias(
    object: &mut Map<String, Value>,
    canonical_key: &str,
    value: Option<&ManifestAliasValue>,
) {
    if object.contains_key(canonical_key) {
        return;
    }
    if let Some(value) = value {
        object.insert(canonical_key.to_string(), Value::String(value.raw.clone()));
    }
}

fn remove_manifest_aliases(object: &mut Map<String, Value>, aliases: &[&str]) {
    for key in aliases {
        object.remove(*key);
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

fn normalize_manifest_label_alias(value: &str) -> String {
    value.trim().to_string()
}

fn normalize_manifest_path_alias(value: &str) -> String {
    value.trim().to_string()
}

fn normalize_manifest_kind_alias(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn empty_manifest(run_id: &str) -> RunArtifactManifest {
    RunArtifactManifest {
        run_id: run_id.to_string(),
        artifacts: Vec::new(),
        objects: Vec::new(),
    }
}

fn write_manifest(target: impl AsRef<Path>, manifest: &RunArtifactManifest) -> Result<PathBuf> {
    let path = manifest_path(target, &manifest.run_id);
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
            path: run_artifact_path(target, run_id, self.leaf).display().to_string(),
            kind: self.kind.to_string(),
        }
    }
}

fn manifest_path(target: impl AsRef<Path>, run_id: &str) -> PathBuf {
    run_artifact_path(target, run_id, manifest_artifact_spec().leaf)
}

fn manifest_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec("artifacts.json")
        .expect("artifact manifest must be in shared spec")
}
