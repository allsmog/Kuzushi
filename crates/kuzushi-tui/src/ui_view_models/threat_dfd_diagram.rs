//! Shared parser for the persisted threat-model DFD.
//!
//! Renderers consume the resulting node/flow model through the contextual DFD
//! deck; the retired whole-screen Workbench ASCII projection no longer owns a
//! second diagram representation.

// Generous bounds — real models stay well under; the renderer pages per zone
// instead of silently dropping topology.
const MAX_NODES: usize = 64;
const MAX_FLOWS: usize = 64;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DfdNode {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) zone: String,
    /// Raw node type from the doc (`process` | `external-entity` | `data-store`).
    pub(crate) kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DfdFlow {
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) label: String,
    pub(crate) crosses: bool,
    /// Trust-boundary ids the doc tags on this flow (may be empty).
    pub(crate) boundary_ids: Vec<String>,
}

pub(crate) fn parse_nodes(doc: &serde_json::Value) -> Vec<DfdNode> {
    doc.pointer("/dfd/nodes")
        .and_then(serde_json::Value::as_array)
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(node_from_value)
                .take(MAX_NODES)
                .collect()
        })
        .unwrap_or_default()
}

fn node_from_value(value: &serde_json::Value) -> Option<DfdNode> {
    let id = string_field(value, "id")?;
    let name = string_field(value, "name").unwrap_or_else(|| id.clone());
    let zone = string_field(value, "trustZone").unwrap_or_else(|| "unzoned".to_string());
    let kind = string_field(value, "type").unwrap_or_else(|| "process".to_string());
    Some(DfdNode {
        id,
        name,
        zone,
        kind,
    })
}

pub(crate) fn parse_flows(doc: &serde_json::Value, nodes: &[DfdNode]) -> Vec<DfdFlow> {
    doc.pointer("/dfd/flows")
        .and_then(serde_json::Value::as_array)
        .map(|flows| {
            flows
                .iter()
                .filter_map(|flow| flow_from_value(flow, nodes))
                .take(MAX_FLOWS)
                .collect()
        })
        .unwrap_or_default()
}

fn flow_from_value(value: &serde_json::Value, nodes: &[DfdNode]) -> Option<DfdFlow> {
    let source_id = string_field(value, "sourceId")?;
    let target_id = string_field(value, "targetId")?;
    let boundary_ids = trust_boundary_ids(value);
    Some(DfdFlow {
        source: display_name(nodes, &source_id),
        target: display_name(nodes, &target_id),
        label: string_field(value, "description").unwrap_or_default(),
        crosses: flow_crosses(value, &boundary_ids, nodes, &source_id, &target_id),
        boundary_ids,
    })
}

fn trust_boundary_ids(value: &serde_json::Value) -> Vec<String> {
    value
        .get("trustBoundaryIds")
        .and_then(serde_json::Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(|id| id.as_str().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// A flow crosses a trust boundary when the doc explicitly tags it with
/// boundary ids; docs without the field fall back to zone inequality. This
/// keeps the legend's crossing count consistent with the model's own
/// boundary list instead of over/under-counting from zone names alone.
fn flow_crosses(
    value: &serde_json::Value,
    boundary_ids: &[String],
    nodes: &[DfdNode],
    source_id: &str,
    target_id: &str,
) -> bool {
    if value.get("trustBoundaryIds").is_some() {
        return !boundary_ids.is_empty();
    }
    zone_of(nodes, source_id) != zone_of(nodes, target_id)
}

pub(crate) fn zones_in_order(nodes: &[DfdNode]) -> Vec<String> {
    let mut zones: Vec<String> = Vec::new();
    for node in nodes {
        if !zones.iter().any(|zone| zone == &node.zone) {
            zones.push(node.zone.clone());
        }
    }
    zones
}

fn zone_of(nodes: &[DfdNode], id: &str) -> String {
    nodes
        .iter()
        .find(|node| node.id == id)
        .map(|node| node.zone.clone())
        .unwrap_or_default()
}

fn display_name(nodes: &[DfdNode], id: &str) -> String {
    nodes
        .iter()
        .find(|node| node.id == id)
        .map(|node| node.name.clone())
        .unwrap_or_else(|| id.to_string())
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_doc() -> serde_json::Value {
        json!({
            "dfd": {
                "nodes": [
                    {"id": "user", "name": "Browser", "trustZone": "internet"},
                    {"id": "api", "name": "API server", "trustZone": "app-tier"},
                    {"id": "db", "name": "Postgres", "trustZone": "data-tier"}
                ],
                "flows": [
                    {"id": "f1", "sourceId": "user", "targetId": "api", "description": "https"},
                    {"id": "f2", "sourceId": "api", "targetId": "db", "description": "sql"}
                ]
            }
        })
    }

    #[test]
    fn parser_preserves_nodes_flows_and_trust_zones_for_the_contextual_deck() {
        let doc = sample_doc();
        let nodes = parse_nodes(&doc);
        let flows = parse_flows(&doc, &nodes);

        assert_eq!(nodes.len(), 3);
        assert_eq!(
            zones_in_order(&nodes),
            ["internet", "app-tier", "data-tier"]
        );
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].source, "Browser");
        assert_eq!(flows[0].target, "API server");
        assert_eq!(flows[0].label, "https");
        assert!(flows.iter().all(|flow| flow.crosses));
    }

    #[test]
    fn parser_is_empty_when_the_artifact_has_no_nodes() {
        assert!(parse_nodes(&json!({})).is_empty());
        assert!(parse_nodes(&json!({"dfd": {"nodes": []}})).is_empty());
    }

    #[test]
    fn boundary_tags_decide_crossings_with_zone_inequality_as_fallback() {
        let doc = json!({
            "dfd": {
                "nodes": [
                    {"id": "a", "name": "A", "trustZone": "app-tier"},
                    {"id": "b", "name": "B", "trustZone": "app-tier"},
                    {"id": "c", "name": "C", "trustZone": "data-tier"}
                ],
                "flows": [
                    // Same zone but explicitly tagged: crosses.
                    {"id": "f1", "sourceId": "a", "targetId": "b", "trustBoundaryIds": ["tb-1"]},
                    // Different zones but explicitly tagged as boundary-free: does not cross.
                    {"id": "f2", "sourceId": "a", "targetId": "c", "trustBoundaryIds": []},
                    // No tag field: zone-inequality fallback.
                    {"id": "f3", "sourceId": "a", "targetId": "c"},
                    {"id": "f4", "sourceId": "a", "targetId": "b"}
                ]
            }
        });
        let nodes = parse_nodes(&doc);
        let flows = parse_flows(&doc, &nodes);

        assert!(flows[0].crosses, "boundary tag wins over same-zone");
        assert_eq!(flows[0].boundary_ids, ["tb-1"]);
        assert!(!flows[1].crosses, "explicit empty tag list wins over zones");
        assert!(flows[2].crosses, "untagged flows fall back to zones");
        assert!(!flows[3].crosses);
    }
}
