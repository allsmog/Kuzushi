use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
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
