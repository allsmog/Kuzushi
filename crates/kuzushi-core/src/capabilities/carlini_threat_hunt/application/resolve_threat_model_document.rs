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
    let document = crate::capabilities::threat_model::try_load_persistent_threat_model(target)
        .with_context(|| format!("Could not load {}", path.display()))?
        .with_context(|| missing_threat_model_message(target, &path))?;
    unwrap_document(document)
}

fn missing_threat_model_message(target: &Path, path: &Path) -> String {
    let artifact = path.strip_prefix(target).unwrap_or(path);
    format!(
        "carlini-threat-hunt requires an existing {} under {}. Run `kuzushi --target {} run threat-model:build` first or provide a document in the tool input.",
        artifact.display(),
        target.display(),
        target.display()
    )
}

pub(crate) fn unwrap_document(value: Value) -> Result<Value> {
    if let Some(document) = value.get("document") {
        return unwrap_document(document.clone());
    }
    if !value.pointer("/dfd/nodes").is_some() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn persisted_threat_model_rejects_symlink_outside_target() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let outside = temp.path().join("outside-threat-model.json");
        let artifact = crate::capabilities::threat_model::persistent_threat_model_path(&target);
        fs::create_dir_all(artifact.parent().unwrap()).unwrap();
        fs::write(
            &outside,
            r#"{"dfd":{"nodes":[]},"marker":"OUTSIDE_CARLINI_MODEL_TOKEN"}"#,
        )
        .unwrap();
        symlink(&outside, &artifact).unwrap();

        let error = resolve_threat_model_document(&json!({}), &target).unwrap_err();

        assert!(!error.to_string().contains("OUTSIDE_CARLINI_MODEL_TOKEN"));
    }
}
