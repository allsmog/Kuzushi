use super::*;

pub(crate) fn apply_agentic_static_validation(
    finding: &mut Finding,
    validation: &StaticProofValidation,
) {
    finding.set_static_proof_state(validation.final_state);
    if validation.accepted {
        if !validation.verified_citations.is_empty() {
            finding.message.push_str("\nVerified citations: ");
            finding
                .message
                .push_str(&validation.verified_citations.len().to_string());
        }
        return;
    }
    finding
        .message
        .push_str("\nWhitebox citation validation: downgraded to needs_runtime_evidence.");
    for issue in validation.issues.iter().take(6) {
        finding.message.push_str("\n- ");
        finding.message.push_str(issue);
    }
}

pub(crate) fn resolve_agentic_schema_file_path(object: &Map<String, Value>) -> String {
    read_literal_path(object)
        .or_else(|| read_nested_object_path(object, "source"))
        .or_else(|| read_nested_object_path(object, "sink"))
        .or_else(|| first_citation_path(object))
        .unwrap_or_else(|| "unknown".to_string())
}

fn read_literal_path(object: &Map<String, Value>) -> Option<String> {
    ["filePath", "file_path"].iter().find_map(|key| {
        object
            .get(*key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

fn read_nested_object_path(object: &Map<String, Value>, nested_key: &str) -> Option<String> {
    object
        .get(nested_key)
        .and_then(Value::as_object)
        .and_then(read_literal_path)
}

pub(crate) fn read_nested_object_u64(
    object: &Map<String, Value>,
    nested_key: &str,
    keys: &[&str],
) -> Option<u64> {
    object
        .get(nested_key)
        .and_then(Value::as_object)
        .and_then(|nested| read_object_u64(nested, keys))
}

fn first_citation_path(object: &Map<String, Value>) -> Option<String> {
    object
        .get("citations")
        .and_then(Value::as_array)
        .and_then(|citations| citations.first())
        .and_then(Value::as_object)
        .and_then(read_literal_path)
}

pub(crate) fn first_citation_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    object
        .get("citations")
        .and_then(Value::as_array)
        .and_then(|citations| citations.first())
        .and_then(Value::as_object)
        .and_then(|citation| read_object_u64(citation, keys))
}

pub(crate) fn append_agentic_schema_field(
    message: &mut String,
    object: &Map<String, Value>,
    key: &str,
    label: &str,
) {
    if let Some(value) = read_object_string(object, &[key]) {
        if !value.trim().is_empty() {
            message.push('\n');
            message.push_str(label);
            message.push_str(": ");
            message.push_str(value.trim());
        }
    }
}

pub(crate) fn append_agentic_schema_object_summary(
    message: &mut String,
    object: &Map<String, Value>,
    key: &str,
    label: &str,
) {
    let Some(value) = object.get(key).and_then(Value::as_object) else {
        return;
    };
    let summary = read_object_string(value, &["description", "explanation", "status", "kind"])
        .filter(|text| !text.trim().is_empty());
    let Some(summary) = summary else {
        return;
    };
    message.push('\n');
    message.push_str(label);
    message.push_str(": ");
    message.push_str(summary.trim());
}

pub(crate) fn agentic_severity(value: &str) -> Severity {
    Severity::from_scanner_label(value)
}

pub(crate) fn read_object_value<'a>(
    object: &'a Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|key| object.get(*key))
}

pub(crate) fn read_object_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    read_object_value(object, keys)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn read_object_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    read_object_value(object, keys).and_then(Value::as_u64)
}

pub(crate) fn normalize_reported_file_path(path: String, target: &Path) -> String {
    crate::findings::normalize_reported_source_path(path, target)
}
