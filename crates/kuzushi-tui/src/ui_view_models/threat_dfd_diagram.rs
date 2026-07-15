//! Shared parser for the persisted threat-model DFD.
//!
//! Renderers consume the resulting node/flow model through the contextual DFD
//! deck; the retired whole-screen Workbench ASCII projection no longer owns a
//! second diagram representation.

const MAX_NODES: usize = 18;
const MAX_FLOWS: usize = 14;
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
    let source_zone = zone_of(nodes, &source_id);
    let target_zone = zone_of(nodes, &target_id);
    Some(DfdFlow {
        source: display_name(nodes, &source_id),
        target: display_name(nodes, &target_id),
        label: string_field(value, "description").unwrap_or_default(),
        crosses: source_zone != target_zone,
    })
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
}
