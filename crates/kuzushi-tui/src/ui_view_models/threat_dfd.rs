use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatDfdNode {
    pub(crate) id: String,
    pub(crate) node_type: String,
    pub(crate) trust_zone: String,
}

pub(crate) fn threat_dfd_nodes(app: &ShellApp) -> Vec<ThreatDfdNode> {
    super::threat_model_doc(app)
        .as_ref()
        .and_then(threat_dfd_nodes_from_doc)
        .unwrap_or_default()
}

pub(crate) fn threat_dfd_nodes_from_doc(doc: &serde_json::Value) -> Option<Vec<ThreatDfdNode>> {
    let nodes = doc.pointer("/dfd/nodes")?.as_array()?;
    if nodes.is_empty() {
        return None;
    }
    let rows = nodes
        .iter()
        .filter_map(threat_dfd_node_from_value)
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return None;
    }
    Some(rows)
}

fn threat_dfd_node_from_value(value: &serde_json::Value) -> Option<ThreatDfdNode> {
    Some(ThreatDfdNode {
        id: string_field(value, "id")?,
        node_type: string_field(value, "type").unwrap_or_else(|| "node".to_string()),
        trust_zone: string_field(value, "trustZone").unwrap_or_default(),
    })
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn threat_dfd_nodes_from_doc_returns_id_type_zone_triples() {
        let doc = json!({
            "dfd": {
                "nodes": [
                    {"id": "actor-user", "type": "external-entity", "name": "User",
                     "description": "End user", "trustZone": "external"},
                    {"id": "web", "type": "process", "name": "Web app",
                     "description": "Server", "trustZone": "internal"}
                ]
            }
        });

        let nodes = threat_dfd_nodes_from_doc(&doc).expect("expected non-empty nodes");

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].id, "actor-user");
        assert_eq!(nodes[0].node_type, "external-entity");
        assert_eq!(nodes[0].trust_zone, "external");
        assert_eq!(nodes[1].id, "web");
        assert_eq!(nodes[1].trust_zone, "internal");
    }

    #[test]
    fn threat_dfd_nodes_from_doc_returns_none_when_missing() {
        assert!(threat_dfd_nodes_from_doc(&json!({})).is_none());
        assert!(threat_dfd_nodes_from_doc(&json!({"dfd": {}})).is_none());
        assert!(threat_dfd_nodes_from_doc(&json!({"dfd": {"nodes": []}})).is_none());
    }
}
