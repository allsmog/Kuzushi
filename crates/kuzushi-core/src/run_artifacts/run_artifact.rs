use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunArtifact {
    #[serde(deserialize_with = "deserialize_artifact_label")]
    pub label: String,
    #[serde(deserialize_with = "deserialize_trimmed_string")]
    pub path: String,
    #[serde(deserialize_with = "deserialize_artifact_kind")]
    pub kind: String,
}

impl RunArtifact {
    pub(crate) fn from_declared(label: &str, path: &str, kind: Option<&str>) -> Option<Self> {
        let path = trimmed_non_empty(path)?;
        Some(Self {
            label: normalize_artifact_label(label),
            path: path.to_string(),
            kind: normalize_artifact_kind(path, kind),
        })
    }

    pub(crate) fn normalized(&self) -> Option<Self> {
        Self::from_declared(&self.label, &self.path, Some(&self.kind))
    }
}

pub(crate) fn normalize_run_artifact_identity(
    target: &Path,
    run_id: &str,
    artifact: &RunArtifact,
) -> Option<RunArtifact> {
    let mut artifact = artifact.normalized()?;
    artifact.path = normalize_run_artifact_path(target, run_id, &artifact.path);
    Some(artifact)
}

pub(crate) fn normalize_run_artifact_identities(
    target: &Path,
    run_id: &str,
    artifacts: Vec<RunArtifact>,
) -> Vec<RunArtifact> {
    let mut normalized = Vec::new();
    for artifact in artifacts {
        if let Some(artifact) = normalize_run_artifact_identity(target, run_id, &artifact) {
            upsert_by_path(&mut normalized, artifact);
        }
    }
    normalized
}

pub(crate) fn normalize_run_artifact_path(target: &Path, run_id: &str, value: &str) -> String {
    let value = value.trim();
    run_contained_relative_path(target, run_id, Path::new(value))
        .and_then(|path| ArtifactPath::parse(path).ok())
        .map(|path| slash_separated(path.as_path()))
        .unwrap_or_else(|| value.to_string())
}

fn run_contained_relative_path(target: &Path, run_id: &str, path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return Some(relative_declared_path(target, run_id, path));
    }
    absolute_run_roots(target, run_id)
        .into_iter()
        .find_map(|root| path.strip_prefix(root).ok().map(Path::to_path_buf))
}

fn relative_declared_path(target: &Path, run_id: &str, path: &Path) -> PathBuf {
    let target_relative_root = run_dir(Path::new(""), run_id);
    let target_named_root = run_dir(target, run_id);
    path.strip_prefix(&target_relative_root)
        .or_else(|_| path.strip_prefix(&target_named_root))
        .map_or_else(|_| path.to_path_buf(), Path::to_path_buf)
}

fn absolute_run_roots(target: &Path, run_id: &str) -> Vec<PathBuf> {
    let mut roots = vec![run_dir(target, run_id)];
    if let Ok(canonical_target) = fs::canonicalize(target) {
        let canonical = run_dir(canonical_target, run_id);
        if !roots.contains(&canonical) {
            roots.push(canonical);
        }
    }
    roots
}

fn slash_separated(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn upsert_by_path(artifacts: &mut Vec<RunArtifact>, artifact: RunArtifact) {
    if let Some(existing) = artifacts.iter_mut().find(|item| item.path == artifact.path) {
        *existing = artifact;
    } else {
        artifacts.push(artifact);
    }
}

fn deserialize_artifact_label<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let label = String::deserialize(deserializer)?;
    Ok(normalize_artifact_label(&label))
}

fn deserialize_trimmed_string<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path = String::deserialize(deserializer)?;
    Ok(path.trim().to_string())
}

fn deserialize_artifact_kind<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let kind = String::deserialize(deserializer)?;
    Ok(normalize_artifact_kind("", Some(&kind)))
}

fn normalize_artifact_label(label: &str) -> String {
    let label = label.trim();
    if label.is_empty() {
        "artifact".to_string()
    } else {
        label.to_string()
    }
}

fn normalize_artifact_kind(path: &str, kind: Option<&str>) -> String {
    kind.and_then(trimmed_non_empty)
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| infer_artifact_kind(path))
}

fn trimmed_non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn infer_artifact_kind(path: &str) -> String {
    let path = Path::new(path);
    if path.is_dir() {
        return "directory".to_string();
    }
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => "json",
        Some("jsonl") => "jsonl",
        Some("md") | Some("markdown") => "markdown",
        Some("sarif") => "sarif",
        _ => "artifact",
    }
    .to_string()
}
