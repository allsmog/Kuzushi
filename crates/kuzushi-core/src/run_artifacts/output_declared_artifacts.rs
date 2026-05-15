use super::artifact_manifest::record_run_artifact;
use super::RunArtifact;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::Path;

pub(crate) fn record_output_declared_artifacts(
    target: &Path,
    run_id: &str,
    output: &Value,
) -> Vec<RunArtifact> {
    let mut seen = BTreeSet::new();
    let mut recorded = Vec::new();
    for artifact in output_artifact_candidates(output) {
        if !seen.insert(artifact.path.clone()) {
            continue;
        }
        if record_run_artifact(target, run_id, &artifact).is_ok() {
            recorded.push(artifact);
        }
    }
    recorded
}

fn output_artifact_candidates(output: &Value) -> Vec<RunArtifact> {
    let mut artifacts = Vec::new();
    append_artifact_value(&mut artifacts, "artifact", output.get("artifacts"));
    append_artifact_value(&mut artifacts, "artifact", output.pointer("/data/artifacts"));
    artifacts
}

fn append_artifact_value(artifacts: &mut Vec<RunArtifact>, label: &str, value: Option<&Value>) {
    match value {
        Some(Value::Array(items)) => append_artifact_items(artifacts, label, items),
        Some(Value::Object(items)) => append_artifact_entries(artifacts, items),
        _ => {}
    }
}

fn append_artifact_items(artifacts: &mut Vec<RunArtifact>, label: &str, items: &[Value]) {
    for item in items {
        append_artifact_item(artifacts, label, item);
    }
}

fn append_artifact_entries(artifacts: &mut Vec<RunArtifact>, items: &Map<String, Value>) {
    for (label, item) in items {
        append_artifact_item(artifacts, label, item);
    }
}

fn append_artifact_item(artifacts: &mut Vec<RunArtifact>, label: &str, value: &Value) {
    if let Some(artifact) = artifact_from_value(label, value) {
        artifacts.push(artifact);
    }
}

fn artifact_from_value(label: &str, value: &Value) -> Option<RunArtifact> {
    match value {
        Value::String(path) => artifact_from_path(label, path, None),
        Value::Object(object) => artifact_from_object(label, object),
        _ => None,
    }
}

fn artifact_from_object(label: &str, object: &Map<String, Value>) -> Option<RunArtifact> {
    let path = first_string(object, &ARTIFACT_PATH_KEYS)?;
    let label = first_string(object, &ARTIFACT_LABEL_KEYS).unwrap_or(label);
    let kind = first_string(object, &ARTIFACT_KIND_KEYS);
    artifact_from_path(label, path, kind)
}

fn artifact_from_path(label: &str, path: &str, kind: Option<&str>) -> Option<RunArtifact> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    Some(RunArtifact {
        label: artifact_label(label),
        path: path.to_string(),
        kind: kind
            .map(str::to_string)
            .unwrap_or_else(|| infer_artifact_kind(path)),
    })
}

fn first_string<'a>(object: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .find_map(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn artifact_label(label: &str) -> String {
    if label.trim().is_empty() {
        "artifact".to_string()
    } else {
        label.to_string()
    }
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

const ARTIFACT_PATH_KEYS: [&str; 9] = [
    "path",
    "file",
    "filePath",
    "reportPath",
    "reportJsonPath",
    "scopePath",
    "dir",
    "outputDir",
    "promptsDir",
];

const ARTIFACT_LABEL_KEYS: [&str; 3] = ["label", "name", "title"];
const ARTIFACT_KIND_KEYS: [&str; 2] = ["kind", "type"];
