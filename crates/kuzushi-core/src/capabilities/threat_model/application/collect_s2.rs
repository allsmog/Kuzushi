use super::*;

pub(crate) fn collect_s2_databases(
    s2: &serde_json::Map<String, Value>,
    nodes: &mut BTreeMap<String, Value>,
) {
    for database in records(s2.get("databases")) {
        let Some(id) = str_field(database, &["id"]) else {
            continue;
        };
        let name = str_field(database, &["name"]).unwrap_or_else(|| id.clone());
        insert_node(
            nodes,
            &id,
            "data-store",
            &name,
            str_field(database, &["description"])
                .as_deref()
                .unwrap_or(&name),
            "internal",
        );
    }
}

pub(crate) fn collect_s2_components(
    s2: &serde_json::Map<String, Value>,
    nodes: &mut BTreeMap<String, Value>,
) {
    let Some(components) = s2.get("components").and_then(Value::as_object) else {
        return;
    };
    for (kind, list) in components {
        for component in records(Some(list)) {
            let Some(id) = str_field(component, &["id", "name"]) else {
                continue;
            };
            let name = str_field(component, &["name"]).unwrap_or_else(|| id.clone());
            insert_node(
                nodes,
                &id,
                component_kind_to_dfd_type(kind),
                &name,
                str_field(component, &["description"])
                    .as_deref()
                    .unwrap_or(kind),
                str_field(component, &["trust_zone", "trustZone"])
                    .as_deref()
                    .unwrap_or("internal"),
            );
        }
    }
}

pub(crate) fn collect_s3_decomposition_parts(
    artifacts: &RandoriArtifacts,
    nodes: &mut BTreeMap<String, Value>,
    flows: &mut BTreeMap<String, Value>,
    trust_boundaries: &mut BTreeMap<String, Value>,
) {
    let Some(s3) = artifacts
        .s3_decomposition
        .as_ref()
        .and_then(Value::as_object)
    else {
        return;
    };
    collect_s3_standard_nodes(s3, nodes);
    collect_s3_dfd_elements(s3, nodes);
    collect_flows(s3.get("data_flows"), flows);
    collect_s3_trust_boundaries(s3, flows, trust_boundaries);
}

pub(crate) fn collect_s3_standard_nodes(
    s3: &serde_json::Map<String, Value>,
    nodes: &mut BTreeMap<String, Value>,
) {
    for (key, default_type, default_zone) in [
        ("external_entities", "external-entity", "external"),
        ("entry_points", "process", "entrypoint"),
        ("processes", "process", "internal"),
        ("data_stores", "data-store", "internal"),
    ] {
        for item in records(s3.get(key)) {
            let Some(id) = str_field(item, &["id"]) else {
                continue;
            };
            let name = str_field(item, &["name"]).unwrap_or_else(|| id.clone());
            insert_node(
                nodes,
                &id,
                default_type,
                &name,
                str_field(item, &["description", "notes"])
                    .as_deref()
                    .unwrap_or(&name),
                str_field(item, &["trust_zone", "trustZone"])
                    .as_deref()
                    .unwrap_or(default_zone),
            );
        }
    }
}
