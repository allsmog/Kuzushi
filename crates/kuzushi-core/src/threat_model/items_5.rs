use super::prelude::*;
use super::*;

pub(crate) fn read_randori_artifacts(root: &Path, output_dir: &str) -> RandoriArtifacts {
    let dir = resolve_output_dir(root, output_dir);
    RandoriArtifacts {
        state: read_json_optional(&dir.join("randori-state.json")),
        s1_objectives: read_json_optional(&dir.join("pasta-s1.json")),
        s2_scope: read_json_optional(&dir.join("pasta-s2.json")),
        s3_decomposition: read_json_optional(&dir.join("pasta-s3.json")),
        s4_threats: read_json_optional(&dir.join("pasta-s4.json")),
        narrative: read_json_optional(&dir.join("pasta-narrative.json")),
    }
}

pub(crate) fn convert_randori_artifacts_to_document(
    artifacts: &RandoriArtifacts,
    methodology: &str,
) -> Result<Option<Value>> {
    if artifacts.s2_scope.is_none()
        && artifacts.s3_decomposition.is_none()
        && artifacts.s4_threats.is_none()
    {
        return Ok(None);
    }

    let mut nodes = BTreeMap::<String, Value>::new();
    let mut flows = BTreeMap::<String, Value>::new();
    let mut trust_boundaries = BTreeMap::<String, Value>::new();

    collect_s2_scope_parts(artifacts, &mut nodes, &mut flows);
    collect_s3_decomposition_parts(artifacts, &mut nodes, &mut flows, &mut trust_boundaries);

    let threats = artifacts
        .s4_threats
        .as_ref()
        .and_then(Value::as_object)
        .map(parse_threats)
        .unwrap_or_default();
    let narrative = artifacts.narrative.as_ref().and_then(parse_narrative);
    let summary = build_summary(&threats);
    let document = json!({
        "version": "2.0",
        "methodology": methodology,
        "dfd": {
            "nodes": nodes.into_values().collect::<Vec<_>>(),
            "flows": flows.into_values().collect::<Vec<_>>(),
            "trustBoundaries": trust_boundaries.into_values().collect::<Vec<_>>(),
        },
        "threats": threats,
        "summary": summary,
    });
    let mut document = normalize_document(document, methodology)?;
    if let Some(narrative) = narrative {
        if let Some(object) = document.as_object_mut() {
            object.insert("narrative".to_string(), narrative);
        }
    }
    Ok(Some(document))
}

pub(crate) fn collect_s2_scope_parts(
    artifacts: &RandoriArtifacts,
    nodes: &mut BTreeMap<String, Value>,
    flows: &mut BTreeMap<String, Value>,
) {
    let Some(s2) = artifacts.s2_scope.as_ref().and_then(Value::as_object) else {
        return;
    };
    collect_s2_actors(s2, nodes);
    collect_s2_services(s2, nodes);
    collect_s2_databases(s2, nodes);
    collect_s2_components(s2, nodes);
    collect_flows(s2.get("data_flows"), flows);
}

pub(crate) fn collect_s2_actors(
    s2: &serde_json::Map<String, Value>,
    nodes: &mut BTreeMap<String, Value>,
) {
    for actor in records(s2.get("actors")) {
        let Some(id) = str_field(actor, &["id"]) else {
            continue;
        };
        let name = str_field(actor, &["name"]).unwrap_or_else(|| id.clone());
        insert_node(
            nodes,
            &id,
            actor_type_to_dfd_type(str_field(actor, &["type"]).as_deref().unwrap_or("")),
            &name,
            str_field(actor, &["description"])
                .as_deref()
                .unwrap_or(&name),
            str_field(actor, &["trust_zone", "trustZone", "trust_level"])
                .as_deref()
                .unwrap_or("external"),
        );
    }
}

pub(crate) fn collect_s2_services(
    s2: &serde_json::Map<String, Value>,
    nodes: &mut BTreeMap<String, Value>,
) {
    for service in records(s2.get("services")) {
        let Some(id) = str_field(service, &["id"]) else {
            continue;
        };
        let name = str_field(service, &["name"]).unwrap_or_else(|| id.clone());
        insert_node(
            nodes,
            &id,
            "process",
            &name,
            str_field(service, &["description"])
                .as_deref()
                .unwrap_or(&name),
            "internal",
        );
    }
}
