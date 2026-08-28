use super::*;

pub(crate) fn validate_persisted_threat_model(
    document: &Value,
    expected_methodology: &str,
) -> Result<()> {
    let object = document
        .as_object()
        .context("ThreatModelDocument must be a JSON object")?;
    require_nonempty_string(object, "version")?;
    let methodology = require_nonempty_string(object, "methodology")?;
    anyhow::ensure!(
        methodology.eq_ignore_ascii_case(expected_methodology),
        "ThreatModelDocument methodology {methodology:?} does not match lineage methodology {expected_methodology:?}"
    );
    require_object(object, "dfd")?;
    require_array(document, "/dfd/nodes")?;
    require_array(document, "/dfd/flows")?;
    require_array(document, "/dfd/trustBoundaries")?;
    require_array(document, "/threats")?;
    require_object(object, "summary")?;
    require_complete_security_context_links(document)
}

pub(crate) fn validate_legacy_threat_model(document: &Value) -> Result<()> {
    let object = document
        .as_object()
        .context("legacy ThreatModelDocument must be a JSON object")?;
    if object.contains_key("dfd") {
        require_complete_security_context_links(document)?;
    }
    Ok(())
}

fn require_nonempty_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("ThreatModelDocument.{field} must be a non-empty string"))
}

fn require_object<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a Map<String, Value>> {
    object
        .get(field)
        .and_then(Value::as_object)
        .with_context(|| format!("ThreatModelDocument.{field} must be an object"))
}

fn require_array<'a>(document: &'a Value, pointer: &str) -> Result<&'a Vec<Value>> {
    document
        .pointer(pointer)
        .and_then(Value::as_array)
        .with_context(|| format!("ThreatModelDocument{pointer} must be an array"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> Value {
        json!({
            "version": "2.0",
            "methodology": "stride",
            "dfd": {
                "nodes": [{"id": "app"}],
                "flows": [],
                "trustBoundaries": []
            },
            "threats": [],
            "summary": {}
        })
    }

    #[test]
    fn persistence_validation_rejects_incomplete_or_mismatched_documents() {
        assert!(validate_persisted_threat_model(&document(), "stride").is_ok());
        assert!(validate_persisted_threat_model(&json!({"title": "not a model"}), "stride")
            .unwrap_err()
            .to_string()
            .contains("version"));
        assert!(validate_persisted_threat_model(&document(), "pasta")
            .unwrap_err()
            .to_string()
            .contains("does not match"));
    }
}
