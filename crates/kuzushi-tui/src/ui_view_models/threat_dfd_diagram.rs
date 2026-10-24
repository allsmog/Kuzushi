//! Shared parser for the persisted threat-model DFD.
//!
//! Renderers consume the resulting node/flow model through the contextual DFD
//! deck; the retired whole-screen Workbench ASCII projection no longer owns a
//! second diagram representation.

use std::collections::{HashMap, HashSet};

// Saved context documents are bounded at the storage boundary. The renderer
// pages their topology; parsing must preserve every valid graph element.
type NodeIndex<'a> = HashMap<&'a str, &'a DfdNode>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DfdNode {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) purpose: Option<String>,
    pub(crate) zone: String,
    /// Raw node type from the doc (`process` | `external-entity` | `data-store`).
    pub(crate) kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DfdFlow {
    pub(crate) id: String,
    pub(crate) source_id: String,
    pub(crate) target_id: String,
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
        .map(|nodes| nodes.iter().filter_map(node_from_value).collect())
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
        description: string_field(value, "description"),
        purpose: string_field(value, "purpose"),
        zone,
        kind,
    })
}

pub(crate) fn parse_flows(doc: &serde_json::Value, nodes: &[DfdNode]) -> Vec<DfdFlow> {
    let index = index_nodes(nodes);
    doc.pointer("/dfd/flows")
        .and_then(serde_json::Value::as_array)
        .map(|flows| {
            flows
                .iter()
                .filter_map(|flow| flow_from_value(flow, &index))
                .collect()
        })
        .unwrap_or_default()
}

fn index_nodes(nodes: &[DfdNode]) -> NodeIndex<'_> {
    let mut index = HashMap::with_capacity(nodes.len());
    for node in nodes {
        index.entry(node.id.as_str()).or_insert(node);
    }
    index
}

fn flow_from_value(value: &serde_json::Value, nodes: &NodeIndex<'_>) -> Option<DfdFlow> {
    let source_id = string_field(value, "sourceId")?;
    let target_id = string_field(value, "targetId")?;
    let boundary_ids = trust_boundary_ids(value);
    Some(DfdFlow {
        id: string_field(value, "id").unwrap_or_else(|| format!("{source_id}->{target_id}")),
        source_id: source_id.clone(),
        target_id: target_id.clone(),
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
    nodes: &NodeIndex<'_>,
    source_id: &str,
    target_id: &str,
) -> bool {
    if value.get("trustBoundaryIds").is_some() {
        return !boundary_ids.is_empty();
    }
    zone_of(nodes, source_id) != zone_of(nodes, target_id)
}

pub(crate) fn zones_in_order(nodes: &[DfdNode]) -> Vec<String> {
    let mut seen = HashSet::new();
    nodes
        .iter()
        .filter(|node| seen.insert(node.zone.as_str()))
        .map(|node| node.zone.clone())
        .collect()
}

fn zone_of<'a>(nodes: &NodeIndex<'a>, id: &str) -> &'a str {
    nodes
        .get(id)
        .map(|node| node.zone.as_str())
        .unwrap_or_default()
}

fn display_name(nodes: &NodeIndex<'_>, id: &str) -> String {
    nodes
        .get(id)
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

    mod large_graph;

    fn sample_doc() -> serde_json::Value {
        json!({
            "dfd": {
                "nodes": [
                    {"id": "user", "name": "Browser", "trustZone": "internet"},
                    {
                        "id": "api", "name": "API server", "trustZone": "app-tier",
                        "description": "Receives browser requests",
                        "purpose": "Provides the application's remote API"
                    },
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
        assert_eq!(flows[0].source_id, "user");
        assert_eq!(flows[0].target_id, "api");
        assert_eq!(flows[0].source, "Browser");
        assert_eq!(flows[0].target, "API server");
        assert_eq!(flows[0].label, "https");
        assert_eq!(
            nodes[1].description.as_deref(),
            Some("Receives browser requests")
        );
        assert_eq!(
            nodes[1].purpose.as_deref(),
            Some("Provides the application's remote API")
        );
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
