use crate::ShellApp;

const DFD_NODE_LIMIT: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatDfdModel {
    pub(crate) header: String,
    pub(crate) rows: Vec<ThreatDfdRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatDfdRow {
    pub(crate) cells: [String; 3],
}

pub(crate) fn threat_dfd_model(app: &ShellApp) -> Option<ThreatDfdModel> {
    super::threat_model_doc(app)
        .as_ref()
        .and_then(threat_dfd_model_from_doc)
}

pub(crate) fn threat_dfd_model_from_doc(doc: &serde_json::Value) -> Option<ThreatDfdModel> {
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
    Some(threat_dfd_model_from_rows(rows))
}

fn threat_dfd_node_from_value(value: &serde_json::Value) -> Option<ThreatDfdRow> {
    Some(threat_dfd_row(
        string_field(value, "id")?,
        string_field(value, "type").unwrap_or_else(|| "node".to_string()),
        string_field(value, "trustZone").unwrap_or_default(),
    ))
}

fn threat_dfd_row(id: String, node_type: String, trust_zone: String) -> ThreatDfdRow {
    ThreatDfdRow {
        cells: [id, node_type, trust_zone],
    }
}

fn threat_dfd_model_from_rows(rows: Vec<ThreatDfdRow>) -> ThreatDfdModel {
    let node_count = rows.len();
    ThreatDfdModel {
        header: format!("NODES FROM threat-model.json · {node_count}"),
        rows: rows.into_iter().take(DFD_NODE_LIMIT).collect(),
    }
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn threat_dfd_model_from_doc_returns_id_type_zone_triples() {
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

        let model = threat_dfd_model_from_doc(&doc).expect("expected non-empty nodes");

        assert_eq!(model.header, "NODES FROM threat-model.json · 2");
        assert_eq!(model.rows.len(), 2);
        assert_eq!(model.rows[0].cells[0], "actor-user");
        assert_eq!(model.rows[0].cells[1], "external-entity");
        assert_eq!(model.rows[0].cells[2], "external");
        assert_eq!(model.rows[1].cells[0], "web");
        assert_eq!(model.rows[1].cells[2], "internal");
    }

    #[test]
    fn threat_dfd_model_from_doc_caps_visible_rows() {
        let doc = json!({
            "dfd": {
                "nodes": [
                    {"id": "n1"}, {"id": "n2"}, {"id": "n3"},
                    {"id": "n4"}, {"id": "n5"}, {"id": "n6"},
                    {"id": "n7"}, {"id": "n8"}, {"id": "n9"}
                ]
            }
        });

        let model = threat_dfd_model_from_doc(&doc).expect("expected non-empty nodes");

        assert_eq!(model.header, "NODES FROM threat-model.json · 9");
        assert_eq!(model.rows.len(), 8);
        assert_eq!(model.rows[7].cells[0], "n8");
    }

    #[test]
    fn threat_dfd_model_from_doc_returns_none_when_missing() {
        assert!(threat_dfd_model_from_doc(&json!({})).is_none());
        assert!(threat_dfd_model_from_doc(&json!({"dfd": {}})).is_none());
        assert!(threat_dfd_model_from_doc(&json!({"dfd": {"nodes": []}})).is_none());
    }
}
