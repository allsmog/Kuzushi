use super::artifact_manifest::record_run_artifact;
use super::RunArtifact;
use anyhow::Result;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::Path;

pub(crate) fn record_output_declared_artifacts(
    target: &Path,
    run_id: &str,
    output: &Value,
    existing: &[RunArtifact],
) -> Result<Vec<RunArtifact>> {
    let mut seen = existing
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<BTreeSet<_>>();
    let mut recorded = Vec::new();
    for artifact in output_artifact_candidates(output) {
        if !seen.insert(artifact.path.clone()) {
            continue;
        }
        record_run_artifact(target, run_id, &artifact).map_err(|error| {
            anyhow::anyhow!(
                "could not record declared artifact {} for run {run_id}: {error:#}",
                artifact.path
            )
        })?;
        recorded.push(artifact);
    }
    Ok(recorded)
}

fn output_artifact_candidates(output: &Value) -> Vec<RunArtifact> {
    let mut artifacts = Vec::new();
    append_artifact_value(&mut artifacts, "artifact", output.get("artifacts"));
    append_artifact_value(
        &mut artifacts,
        "artifact",
        output.pointer("/data/artifacts"),
    );
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
    let path = nonempty_object_string(object, "path")?;
    let label = nonempty_object_string(object, "label").unwrap_or(label);
    let kind = nonempty_object_string(object, "kind");
    artifact_from_path(label, path, kind)
}

pub(crate) fn artifact_from_path(
    label: &str,
    path: &str,
    kind: Option<&str>,
) -> Option<RunArtifact> {
    RunArtifact::from_declared(label, path, kind)
}

fn nonempty_object_string<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
