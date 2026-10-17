use super::files::{candidate_files, IndexedFile};
use super::patterns::{LeadPattern, LEAD_PATTERNS};
use super::projection::{Elements, Projection};
use serde_json::{json, Value};

pub(super) fn threat_lead(
    threat: &Value,
    nodes: &Elements<'_>,
    flows: &Elements<'_>,
    file_index: &[IndexedFile],
    projection: &mut Projection,
) -> Option<Value> {
    let id = projection.identity(threat, "id")?;
    let threat_text = searchable_threat_text(threat, projection);
    let pattern = best_pattern(&threat_text)?;
    let affected_files = projection.references(threat, "affectedFiles");
    let target_ids = projection.references(threat, "targetElementIds");
    let linked_nodes = linked_nodes(&target_ids, nodes, projection);
    let linked_flows = linked_flows(&target_ids, flows, nodes, projection);
    let candidates = candidate_files(pattern, &affected_files, file_index);
    let confidence = lead_confidence(&candidates);

    Some(json!({
        "threatId": id,
        "title": projection.text(threat, "title").unwrap_or_else(|| id.clone()),
        "category": projection.text(threat, "category"),
        "impact": projection.text(threat, "impact"),
        "likelihood": projection.text(threat, "likelihood"),
        "pattern": pattern.id,
        "source": pattern.source,
        "sink": pattern.sink,
        "candidateFiles": candidates,
        "affectedFiles": affected_files,
        "linkedNodes": linked_nodes,
        "linkedFlows": linked_flows,
        "preconditions": projection.text(threat, "preconditions"),
        "missingMitigations": projection.text(threat, "missingMitigations"),
        "cwe": pattern.cwes,
        "classification": lead_classification(&candidates),
        "confidence": confidence,
    }))
}

fn linked_nodes(
    target_ids: &[String],
    nodes: &Elements<'_>,
    projection: &mut Projection,
) -> Vec<Value> {
    target_ids
        .iter()
        .filter_map(|id| {
            nodes
                .get(id.as_str())
                .map(|node| summarized_node(id, node, projection))
        })
        .collect()
}

fn linked_flows(
    target_ids: &[String],
    flows: &Elements<'_>,
    nodes: &Elements<'_>,
    projection: &mut Projection,
) -> Vec<Value> {
    target_ids
        .iter()
        .filter_map(|id| {
            flows
                .get(id.as_str())
                .map(|flow| summarized_flow(id, flow, nodes, projection))
        })
        .collect()
}

fn lead_confidence(candidates: &[Value]) -> &'static str {
    if candidates.iter().any(has_multiple_evidence_terms) {
        "high"
    } else if candidates.is_empty() {
        "low"
    } else {
        "medium"
    }
}

fn has_multiple_evidence_terms(candidate: &Value) -> bool {
    candidate["evidence"]
        .as_array()
        .is_some_and(|items| items.len() >= 2)
}

fn searchable_threat_text(threat: &Value, projection: &mut Projection) -> String {
    [
        "title",
        "description",
        "impact",
        "attackVector",
        "preconditions",
        "missingMitigations",
        "category",
    ]
    .iter()
    .filter_map(|key| projection.text(threat, key))
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase()
}

fn best_pattern(text: &str) -> Option<&'static LeadPattern> {
    LEAD_PATTERNS
        .iter()
        .max_by_key(|pattern| {
            pattern
                .trigger_terms
                .iter()
                .filter(|term| text.contains(**term))
                .count()
        })
        .filter(|pattern| {
            pattern
                .trigger_terms
                .iter()
                .any(|term| text.contains(*term))
        })
}

fn summarized_node(id: &str, node: &Value, projection: &mut Projection) -> Value {
    json!({
        "id": id,
        "name": projection.text(node, "name"),
        "type": projection.text(node, "type"),
        "trustZone": projection.text(node, "trustZone"),
    })
}

fn summarized_flow(
    id: &str,
    flow: &Value,
    nodes: &Elements<'_>,
    projection: &mut Projection,
) -> Value {
    let source_id = projection.identity(flow, "sourceId");
    let target_id = projection.identity(flow, "targetId");
    json!({
        "id": id,
        "description": projection.text(flow, "description"),
        "sourceId": source_id,
        "targetId": target_id,
        "source": source_id.as_ref().and_then(|id| nodes.get(id.as_str())).and_then(|node| projection.text(node, "name")),
        "target": target_id.as_ref().and_then(|id| nodes.get(id.as_str())).and_then(|node| projection.text(node, "name")),
    })
}

fn lead_classification(candidates: &[Value]) -> &'static str {
    if candidates.iter().all(|candidate| {
        candidate["classification"]
            .as_str()
            .is_some_and(|class| class == "example-code" || class == "test-code")
    }) {
        "example-or-test-only"
    } else {
        "production-or-mixed"
    }
}

pub(super) fn lead_priority(lead: &Value) -> u8 {
    [
        priority_if(
            lead["pattern"].as_str() == Some("remote-path-to-local-write"),
            100,
        ),
        priority_if(
            lead["classification"].as_str() == Some("production-or-mixed"),
            20,
        ),
        priority_if(lead["confidence"].as_str() == Some("high"), 10),
        priority_if(
            lead["title"].as_str().is_some_and(contains_file_write_risk),
            10,
        ),
    ]
    .into_iter()
    .sum()
}

fn priority_if(condition: bool, points: u8) -> u8 {
    if condition {
        points
    } else {
        0
    }
}

fn contains_file_write_risk(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["overwrite", "traversal", "file", "path", "helper"]
        .iter()
        .any(|term| lower.contains(term))
}

pub(super) fn threat_id_number(lead: &Value) -> u32 {
    lead["threatId"]
        .as_str()
        .and_then(|id| id.trim_start_matches('t').parse::<u32>().ok())
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_remote_path_pattern_for_file_overwrite_threat() {
        let pattern = best_pattern(
            "unsafe url-to-file handling in helper paths local file overwrite traversal",
        )
        .expect("pattern");

        assert_eq!(pattern.id, "remote-path-to-local-write");
    }

    #[test]
    fn prioritizes_production_file_write_leads() {
        let low_value = json!({
            "threatId": "t1",
            "title": "Workflow identity spoofing",
            "pattern": "ci-build-supply-chain",
            "classification": "production-or-mixed",
            "confidence": "high",
        });
        let file_write = json!({
            "threatId": "t6",
            "title": "Unsafe URL-to-file handling in helper paths",
            "pattern": "remote-path-to-local-write",
            "classification": "production-or-mixed",
            "confidence": "high",
        });

        assert!(lead_priority(&file_write) > lead_priority(&low_value));
    }
}
