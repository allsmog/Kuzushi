use super::*;

#[test]
fn normalize_dfd_canonicalizes_camelcase_node_types() {
    let mut dfd = json!({
        "nodes": [
            {"id": "n1", "type": "externalEntity", "name": "Client"},
            {"id": "n2", "type": "dataStore", "name": "Tablespace"},
            {"id": "n3", "type": "process", "name": "Server"},
            {"id": "f1", "type": "data-flow", "name": "Dropped flow"},
        ],
        "flows": [],
        "trustBoundaries": [],
    });

    normalize_dfd(&mut dfd);

    let types = dfd
        .get("nodes")
        .and_then(Value::as_array)
        .expect("nodes array")
        .iter()
        .map(|node| node.get("type").and_then(Value::as_str).unwrap_or(""))
        .collect::<Vec<_>>();

    assert_eq!(types, vec!["external-entity", "data-store", "process"]);
}
