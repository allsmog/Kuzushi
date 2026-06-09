use super::*;

pub(crate) fn resolve_threat_model_document(input: &Value, target: &Path) -> Result<Value> {
    if let Some(value) = input
        .get("document")
        .or_else(|| input.get("threatModel"))
        .or_else(|| input.get("threat_model"))
    {
        return unwrap_document(value.clone());
    }
    let path = crate::capabilities::threat_model::persistent_threat_model_path(target);
    let raw = fs::read_to_string(&path).with_context(|| {
        let artifact = path.strip_prefix(target).unwrap_or(path.as_path());
        format!(
            "carlini-threat-hunt requires an existing {} under {}. Run `kuzushi --target {} run threat-model:build` first or provide a document in the tool input.",
            artifact.display(),
            target.display(),
            target.display()
        )
    })?;
    let parsed = serde_json::from_str::<Value>(&raw)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    unwrap_document(parsed)
}

pub(crate) fn unwrap_document(value: Value) -> Result<Value> {
    if let Some(document) = value.get("document") {
        return unwrap_document(document.clone());
    }
    if value.pointer("/dfd/nodes").is_none() {
        anyhow::bail!("carlini-threat-hunt threat model document is missing dfd.nodes");
    }
    Ok(value)
}

pub(crate) fn parse_node(value: &Value) -> Option<DfdNode> {
    let object = value.as_object()?;
    let id = read_object_string(object, &["id"])?;
    Some(DfdNode {
        id: id.clone(),
        node_type: read_object_string(object, &["type"]).unwrap_or_else(|| "process".to_string()),
        name: read_object_string(object, &["name"]).unwrap_or_else(|| id.clone()),
        description: read_object_string(object, &["description"]).unwrap_or_else(|| id.clone()),
        trust_zone: read_object_string(object, &["trustZone", "trust_zone"])
            .unwrap_or_else(|| "unknown".to_string()),
    })
}

pub(crate) fn parse_flow(value: &Value) -> Option<DfdFlow> {
    let object = value.as_object()?;
    let id = read_object_string(object, &["id"])?;
    Some(DfdFlow {
        id: id.clone(),
        source_id: read_object_string(object, &["sourceId", "source_id", "source"])?,
        target_id: read_object_string(object, &["targetId", "target_id", "target", "destination"])?,
        description: read_object_string(object, &["description", "name"])
            .unwrap_or_else(|| id.clone()),
        trust_boundary_ids: read_object_string_array(
            object,
            &["trustBoundaryIds", "trust_boundary_ids", "crosses"],
        ),
        protocol: read_object_string(object, &["protocol"]),
        data_classification: read_object_string(
            object,
            &[
                "dataClassification",
                "data_classification",
                "classification",
            ],
        ),
    })
}
