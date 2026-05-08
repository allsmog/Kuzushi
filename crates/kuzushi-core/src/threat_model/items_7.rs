use super::prelude::*;
use super::*;

pub(crate) fn collect_s3_dfd_elements(
    s3: &serde_json::Map<String, Value>,
    nodes: &mut BTreeMap<String, Value>,
) {
    for item in records_or_record_collections(s3.get("dfd_elements")) {
        let Some(id) = str_field(item, &["id"]) else {
            continue;
        };
        let name = str_field(item, &["name"]).unwrap_or_else(|| id.clone());
        insert_node(
            nodes,
            &id,
            normalize_dfd_type(str_field(item, &["type"]).as_deref().unwrap_or("process")),
            &name,
            str_field(item, &["description"])
                .as_deref()
                .unwrap_or(&name),
            str_field(item, &["trust_zone", "trustZone", "component"])
                .as_deref()
                .unwrap_or("unknown"),
        );
    }
}

pub(crate) fn collect_s3_trust_boundaries(
    s3: &serde_json::Map<String, Value>,
    flows: &BTreeMap<String, Value>,
    trust_boundaries: &mut BTreeMap<String, Value>,
) {
    for boundary in records(s3.get("trust_boundaries")) {
        let Some(id) = str_field(boundary, &["id"]) else {
            continue;
        };
        let name = str_field(boundary, &["name"]).unwrap_or_else(|| id.clone());
        let crossings = crossing_flow_ids(boundary, flows, &id);
        trust_boundaries.insert(
            id.clone(),
            json!({
                "id": id,
                "name": name,
                "innerZone": str_field(boundary, &["inner_zone", "innerZone"]).unwrap_or_else(|| "internal".to_string()),
                "outerZone": str_field(boundary, &["outer_zone", "outerZone"]).unwrap_or_else(|| "external".to_string()),
                "crossingFlowIds": crossings,
            }),
        );
    }
}

pub(crate) fn crossing_flow_ids(
    boundary: &Map<String, Value>,
    flows: &BTreeMap<String, Value>,
    boundary_id: &str,
) -> Vec<String> {
    let mut crossings = string_array_field(
        boundary,
        &[
            "crossing_flow_ids",
            "crossingFlowIds",
            "crossing_flows",
            "flows",
        ],
    );
    for flow in flows.values() {
        let includes = flow
            .get("trustBoundaryIds")
            .and_then(Value::as_array)
            .is_some_and(|ids| ids.iter().any(|value| value.as_str() == Some(boundary_id)));
        if includes {
            if let Some(flow_id) = flow.get("id").and_then(Value::as_str) {
                crossings.push(flow_id.to_string());
            }
        }
    }
    crossings.sort();
    crossings.dedup();
    crossings
}

pub(crate) fn collect_flows(raw: Option<&Value>, flows: &mut BTreeMap<String, Value>) {
    for item in records(raw) {
        let Some(id) = str_field(item, &["id"]) else {
            continue;
        };
        let Some(source) = str_field(item, &["source_id", "sourceId", "source", "from"]) else {
            continue;
        };
        let Some(target) = str_field(
            item,
            &["target_id", "targetId", "target", "destination", "to"],
        ) else {
            continue;
        };
        let name = str_field(item, &["name", "label", "data"])
            .unwrap_or_else(|| format!("{source} -> {target}"));
        flows.entry(id.clone()).or_insert_with(|| {
            let trust_boundary_ids =
                string_array_field(item, &["trust_boundary_ids", "trustBoundaryIds", "crosses"]);
            json!({
                "id": id,
                "name": name,
                "description": str_field(item, &["description"]).unwrap_or_else(|| name.clone()),
                "sourceId": source,
                "targetId": target,
                "protocol": str_field(item, &["protocol"]).unwrap_or_default(),
                "dataClassification": str_field(item, &["data_classification", "dataClassification", "classification", "sensitivity"]).unwrap_or_default(),
                "trustBoundaryIds": trust_boundary_ids,
            })
        });
    }
}
