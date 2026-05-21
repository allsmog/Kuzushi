mod artifact_manifest;
mod attack_surface;
mod context;
mod failure;
mod findings;
mod jsonl;
mod proof;
mod recommendations;
mod result;
mod run_metadata;
mod severity;

use self::artifact_manifest::artifact_manifest_summary;
use self::attack_surface::attack_surface_summary;
use self::context::context_summary;
use self::failure::failure_handoff_summary;
use self::findings::findings_summary;
use self::jsonl::jsonl_summary;
use self::proof::proof_summary;
use self::recommendations::recommendation_summary;
use self::result::result_summary;
use self::run_metadata::run_metadata_summary;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn summarize_text_artifact(file: &str, body: &str) -> String {
    jsonl_summary(file, body).unwrap_or_else(|| format!("{} line(s)", body.lines().count()))
}

pub(super) fn summarize_json_artifact(value: &Value) -> String {
    if let Some(summary) = text_summary(value) {
        return summary;
    }
    match value {
        Value::Array(items) => format!("{} record(s)", items.len()),
        Value::Object(object) => format!("{} top-level field(s)", object.len()),
        _ => "present".to_string(),
    }
}

fn text_summary(value: &Value) -> Option<String> {
    run_metadata_summary(value)
        .or_else(|| artifact_manifest_summary(value))
        .or_else(|| recommendation_summary(value))
        .or_else(|| context_summary(value))
        .or_else(|| result_summary(value))
        .or_else(|| {
            value
                .get("summary")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| proof_summary(value))
        .or_else(|| findings_summary(value))
        .or_else(|| threat_model_summary(value))
        .or_else(|| attack_surface_summary(value))
        .or_else(|| failure_handoff_summary(value))
}

fn threat_model_summary(value: &Value) -> Option<String> {
    let document = threat_model_document(value);
    let threats = array_len(document.get("threats"));
    let dfd = document.get("dfd");
    let nodes = array_len(dfd.and_then(|value| value.get("nodes")));
    let flows = array_len(dfd.and_then(|value| value.get("flows")));
    let boundaries = array_len(dfd.and_then(trust_boundaries_value));
    if threats.is_none() && nodes.is_none() {
        return None;
    }
    let mut parts = methodology_segment(document).into_iter().collect::<Vec<_>>();
    parts.push(format!("{} threat(s)", threats.unwrap_or_default()));
    parts.extend(dfd_segments(nodes, flows, boundaries));
    parts.extend(related_cwe_segment(document));
    parts.extend(narrative_flow_segments(document));
    parts.extend(narrative_story_segments(document));
    Some(parts.join(", "))
}

fn threat_model_document(value: &Value) -> &Value {
    value
        .get("document")
        .or_else(|| value.pointer("/data/document"))
        .unwrap_or(value)
}

fn trust_boundaries_value(dfd: &Value) -> Option<&Value> {
    dfd.get("trustBoundaries")
        .or_else(|| dfd.get("trust_boundaries"))
}

fn methodology_segment(document: &Value) -> Option<String> {
    document
        .get("methodology")
        .and_then(Value::as_str)
        .map(|methodology| format!("methodology {methodology}"))
}

fn dfd_segments(
    nodes: Option<usize>,
    flows: Option<usize>,
    boundaries: Option<usize>,
) -> Vec<String> {
    vec![
        format!("DFD nodes={}", nodes.unwrap_or_default()),
        format!("flows={}", flows.unwrap_or_default()),
        format!("boundaries={}", boundaries.unwrap_or_default()),
    ]
}

fn related_cwe_segment(document: &Value) -> Option<String> {
    let counts = related_cwe_counts(document);
    if counts.is_empty() {
        return None;
    }
    Some(format!("CWEs {}", cwe_count_segments(&counts).join(", ")))
}

fn narrative_flow_segments(document: &Value) -> Vec<String> {
    [
        ("attackerControlled", "/attackerControlled", "/attacker_controlled"),
        ("operatorControlled", "/operatorControlled", "/operator_controlled"),
        ("developerControlled", "/developerControlled", "/developer_controlled"),
        ("externalServices", "/externalServices", "/external_services"),
        ("credentialFlows", "/credentialFlows", "/credential_flows"),
        ("authorizationFlows", "/authorizationFlows", "/authorization_flows"),
        ("fileIngestFlows", "/fileIngestFlows", "/file_ingest_flows"),
        ("dataEgressFlows", "/dataEgressFlows", "/data_egress_flows"),
        ("callbackFlows", "/callbackFlows", "/callback_flows"),
    ]
    .into_iter()
    .filter_map(|(label, camel_leaf, snake_leaf)| narrative_flow_segment(document, label, camel_leaf, snake_leaf))
    .collect()
}

fn narrative_flow_segment(
    document: &Value,
    label: &str,
    camel_leaf: &str,
    snake_leaf: &str,
) -> Option<String> {
    let count = array_len(narrative_flow_value(document, camel_leaf, snake_leaf))?;
    (count > 0).then(|| format!("{label}={count}"))
}

fn narrative_flow_value<'a>(
    document: &'a Value,
    camel_leaf: &str,
    snake_leaf: &str,
) -> Option<&'a Value> {
    [
        format!("/narrative/inputCategories{camel_leaf}"),
        format!("/narrative/inputCategories{snake_leaf}"),
        format!("/narrative/input_categories{camel_leaf}"),
        format!("/narrative/input_categories{snake_leaf}"),
    ]
    .into_iter()
    .find_map(|pointer| document.pointer(&pointer))
}

fn narrative_story_segments(document: &Value) -> Vec<String> {
    [
        ("attackerStories", "/narrative/attackerStories", "/narrative/attacker_stories"),
        ("outOfScope", "/narrative/outOfScope", "/narrative/out_of_scope"),
        (
            "sandboxBoundary",
            "/narrative/inputCategories/sandboxBoundary",
            "/narrative/input_categories/sandbox_boundary",
        ),
        (
            "assumptions",
            "/narrative/inputCategories/assumptions",
            "/narrative/input_categories/assumptions",
        ),
    ]
    .into_iter()
    .filter_map(|(label, camel_pointer, snake_pointer)| {
        narrative_array_count_segment(document, label, camel_pointer, snake_pointer)
    })
    .chain(criticality_bucket_segment(document))
    .collect()
}

fn narrative_array_count_segment(
    document: &Value,
    label: &str,
    camel_pointer: &str,
    snake_pointer: &str,
) -> Option<String> {
    let count = array_len(
        document
            .pointer(camel_pointer)
            .or_else(|| document.pointer(snake_pointer)),
    )?;
    (count > 0).then(|| format!("{label}={count}"))
}

fn criticality_bucket_segment(document: &Value) -> Option<String> {
    let count = document
        .pointer("/narrative/criticalityBuckets")
        .or_else(|| document.pointer("/narrative/criticality_buckets"))?
        .as_object()?
        .len();
    (count > 0).then(|| format!("criticalityBuckets={count}"))
}

fn related_cwe_counts(document: &Value) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    collect_related_cwes(document, &mut counts);
    if let Some(threats) = document.get("threats").and_then(Value::as_array) {
        for threat in threats {
            collect_related_cwes(threat, &mut counts);
        }
    }
    counts
}

fn collect_related_cwes(threat: &Value, counts: &mut BTreeMap<String, usize>) {
    let Some(cwes) = related_cwe_value(threat).and_then(Value::as_array) else {
        return;
    };
    for cwe in cwes.iter().filter_map(Value::as_str).filter(non_empty) {
        *counts.entry(cwe.to_string()).or_insert(0) += 1;
    }
}

fn related_cwe_value(threat: &Value) -> Option<&Value> {
    threat
        .get("relatedCwe")
        .or_else(|| threat.get("related_cwe"))
        .or_else(|| threat.get("cwe"))
}

fn non_empty(value: &&str) -> bool {
    !value.trim().is_empty()
}

fn cwe_count_segments(counts: &BTreeMap<String, usize>) -> Vec<String> {
    counts
        .iter()
        .take(8)
        .map(|(cwe, count)| format!("{cwe}={count}"))
        .collect()
}

fn array_len(value: Option<&Value>) -> Option<usize> {
    value.and_then(Value::as_array).map(Vec::len)
}
