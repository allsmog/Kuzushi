use crate::artifact_contract::{
    first_nonempty_value_string, CanonicalRunArtifactSpec, ARTIFACT_KIND_KEYS,
    ARTIFACT_LABEL_KEYS, ARTIFACT_PATH_KEYS, CANONICAL_RUN_ARTIFACTS, OPTIONAL_RUN_ARTIFACTS,
    TOOL_INPUT_ARTIFACTS, TOOL_RESULT_ARTIFACTS,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn artifact_manifest_summary(value: &Value) -> Option<String> {
    require_manifest_shape(value)?;
    let artifacts = value.get("artifacts").and_then(Value::as_array)?;
    let mut parts = vec![format!("{} artifact(s)", artifacts.len())];
    parts.extend(kind_segment(artifacts));
    parts.extend(canonical_segment(artifacts));
    parts.extend(optional_segment(artifacts));
    parts.extend(tool_input_segment(artifacts));
    parts.extend(tool_result_segment(artifacts));
    parts.extend(alias_segment(artifacts));
    parts.extend(label_segment(artifacts));
    Some(parts.join(", "))
}

fn require_manifest_shape(value: &Value) -> Option<()> {
    value_at(value, &["runId", "run_id"])?;
    value.get("summary").is_none().then_some(())
}

fn kind_segment(artifacts: &[Value]) -> Option<String> {
    let counts = count_string_field(artifacts, &ARTIFACT_KIND_KEYS);
    count_segments(&counts).map(|summary| format!("kinds {summary}"))
}

fn canonical_segment(artifacts: &[Value]) -> Option<String> {
    let count = artifacts.iter().filter(|artifact| canonical_artifact(artifact)).count();
    (count > 0).then(|| format!("canonical {count}"))
}

fn canonical_artifact(artifact: &Value) -> bool {
    manifest_path_matches(artifact, &CANONICAL_RUN_ARTIFACTS)
}

fn optional_segment(artifacts: &[Value]) -> Option<String> {
    let labels = matching_labels(artifacts, &OPTIONAL_RUN_ARTIFACTS);
    (!labels.is_empty()).then(|| format!("optional {}", labels.join(", ")))
}

fn tool_input_segment(artifacts: &[Value]) -> Option<String> {
    let labels = matching_labels(artifacts, &TOOL_INPUT_ARTIFACTS);
    (!labels.is_empty()).then(|| format!("tool inputs {}", labels.join(", ")))
}

fn tool_result_segment(artifacts: &[Value]) -> Option<String> {
    let labels = matching_labels(artifacts, &TOOL_RESULT_ARTIFACTS);
    (!labels.is_empty()).then(|| format!("tool results {}", labels.join(", ")))
}

fn alias_segment(artifacts: &[Value]) -> Option<String> {
    let label = compatibility_alias_count(artifacts, &ARTIFACT_LABEL_KEYS, "label");
    let path = compatibility_alias_count(artifacts, &ARTIFACT_PATH_KEYS, "path");
    let kind = compatibility_alias_count(artifacts, &ARTIFACT_KIND_KEYS, "kind");
    let parts = [
        (label > 0).then(|| format!("labels={label}")),
        (path > 0).then(|| format!("paths={path}")),
        (kind > 0).then(|| format!("kinds={kind}")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    (!parts.is_empty()).then(|| format!("aliases {}", parts.join(", ")))
}

fn compatibility_alias_count(artifacts: &[Value], keys: &[&str], canonical_key: &str) -> usize {
    artifacts
        .iter()
        .filter(|artifact| {
            keys.iter()
                .filter(|key| **key != canonical_key)
                .any(|key| artifact.get(*key).is_some())
        })
        .count()
}

fn matching_labels(artifacts: &[Value], specs: &[CanonicalRunArtifactSpec]) -> Vec<&'static str> {
    specs
        .iter()
        .filter(|spec| {
            artifacts
                .iter()
                .any(|artifact| manifest_path_matches_leaf(artifact, spec.leaf))
        })
        .map(|spec| spec.label)
        .collect()
}

fn manifest_path_matches(artifact: &Value, specs: &[CanonicalRunArtifactSpec]) -> bool {
    specs
        .iter()
        .any(|spec| manifest_path_matches_leaf(artifact, spec.leaf))
}

fn manifest_path_matches_leaf(artifact: &Value, leaf: &str) -> bool {
    first_nonempty_value_string(artifact, &ARTIFACT_PATH_KEYS)
        .is_some_and(|path| path.ends_with(leaf))
}

fn label_segment(artifacts: &[Value]) -> Option<String> {
    let labels = artifacts
        .iter()
        .filter_map(|artifact| first_nonempty_value_string(artifact, &ARTIFACT_LABEL_KEYS))
        .take(4)
        .collect::<Vec<_>>();
    (!labels.is_empty()).then(|| format!("labels {}", labels.join(", ")))
}

fn count_string_field(items: &[Value], keys: &[&str]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for item in items {
        if let Some(value) = first_nonempty_value_string(item, keys) {
            *counts.entry(value.to_string()).or_insert(0) += 1;
        }
    }
    counts
}

fn count_segments(counts: &BTreeMap<String, usize>) -> Option<String> {
    let summary = counts
        .iter()
        .map(|(key, count)| format!("{key}={count}"))
        .collect::<Vec<_>>()
        .join(", ");
    (!summary.is_empty()).then_some(summary)
}

fn value_at<'a>(object: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}
