use super::*;

pub(crate) fn normalize_document(mut value: Value, methodology: &str) -> Result<Value> {
    if value.get("document").is_some() {
        value = value
            .get("document")
            .cloned()
            .context("document wrapper was missing document")?;
    }
    let object = value
        .as_object_mut()
        .with_context(|| "ThreatModelDocument must be a JSON object")?;
    object
        .entry("version".to_string())
        .or_insert_with(|| json!("2.0"));
    object.insert("methodology".to_string(), json!(methodology));

    let mut dfd = object
        .remove("dfd")
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    normalize_dfd(&mut dfd);
    object.insert("dfd".to_string(), dfd);

    let threats = object
        .remove("threats")
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let threats_array = threats.as_array().cloned().unwrap_or_default();
    object.insert("threats".to_string(), Value::Array(threats_array.clone()));
    object.insert("summary".to_string(), build_summary(&threats_array));
    Ok(value)
}

pub(crate) fn normalize_dfd(dfd: &mut Value) {
    let Some(object) = dfd.as_object_mut() else {
        *dfd = json!({"nodes":[],"flows":[],"trustBoundaries":[]});
        return;
    };
    let nodes = object
        .remove("nodes")
        .or_else(|| object.remove("elements"))
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let nodes = nodes
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|mut node| {
            let raw = node
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("process");
            let canonical = normalize_dfd_type(raw);
            if canonical == "data-flow" {
                return None;
            }
            if let Some(object) = node.as_object_mut() {
                object.insert("type".to_string(), Value::String(canonical.to_string()));
            }
            Some(node)
        })
        .collect::<Vec<_>>();
    let flows = object
        .remove("flows")
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let boundaries = object
        .remove("trustBoundaries")
        .or_else(|| object.remove("trust_boundaries"))
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    object.insert("nodes".to_string(), Value::Array(nodes));
    object.insert(
        "flows".to_string(),
        Value::Array(flows.as_array().cloned().unwrap_or_default()),
    );
    object.insert(
        "trustBoundaries".to_string(),
        Value::Array(boundaries.as_array().cloned().unwrap_or_default()),
    );
}

pub(crate) fn apply_methodology(mut document: Value, methodology: &str) -> Result<Value> {
    if let Some(object) = document.as_object_mut() {
        object.insert("methodology".to_string(), json!(methodology));
        if methodology == "dread" {
            let threats = object
                .get("threats")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            object.insert("riskScores".to_string(), build_dread_scores(&threats));
        } else {
            object.remove("riskScores");
        }
    }
    Ok(document)
}

pub(crate) fn build_summary(threats: &[Value]) -> Value {
    let mut by_severity = BTreeMap::<String, usize>::new();
    let mut by_category = BTreeMap::<String, usize>::new();
    for threat in threats {
        if let Some(impact) = threat.get("impact").and_then(Value::as_str) {
            *by_severity.entry(impact.to_string()).or_default() += 1;
        }
        if let Some(category) = threat.get("category").and_then(Value::as_str) {
            *by_category.entry(category.to_string()).or_default() += 1;
        }
    }
    json!({
        "total": threats.len(),
        "bySeverity": by_severity,
        "byCategory": by_category,
    })
}
