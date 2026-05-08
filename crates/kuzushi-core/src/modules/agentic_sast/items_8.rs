use super::prelude::*;
use super::*;

pub(in crate::modules) fn apply_agentic_static_validation(
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

pub(in crate::modules) fn resolve_agentic_schema_file_path(object: &Map<String, Value>) -> String {
    read_object_string(object, &["filePath", "file_path"])
        .or_else(|| read_nested_object_string(object, "source", &["filePath", "file_path"]))
        .or_else(|| read_nested_object_string(object, "sink", &["filePath", "file_path"]))
        .or_else(|| first_citation_string(object, &["filePath", "file_path"]))
        .unwrap_or_else(|| "unknown".to_string())
}

pub(in crate::modules) fn read_nested_object_string(
    object: &Map<String, Value>,
    nested_key: &str,
    keys: &[&str],
) -> Option<String> {
    object
        .get(nested_key)
        .and_then(Value::as_object)
        .and_then(|nested| read_object_string(nested, keys))
}

pub(in crate::modules) fn read_nested_object_u64(
    object: &Map<String, Value>,
    nested_key: &str,
    keys: &[&str],
) -> Option<u64> {
    object
        .get(nested_key)
        .and_then(Value::as_object)
        .and_then(|nested| read_object_u64(nested, keys))
}

pub(in crate::modules) fn first_citation_string(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    object
        .get("citations")
        .and_then(Value::as_array)
        .and_then(|citations| citations.first())
        .and_then(Value::as_object)
        .and_then(|citation| read_object_string(citation, keys))
}

pub(in crate::modules) fn first_citation_u64(
    object: &Map<String, Value>,
    keys: &[&str],
) -> Option<u64> {
    object
        .get("citations")
        .and_then(Value::as_array)
        .and_then(|citations| citations.first())
        .and_then(Value::as_object)
        .and_then(|citation| read_object_u64(citation, keys))
}

pub(in crate::modules) fn append_agentic_schema_field(
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

pub(in crate::modules) fn append_agentic_schema_object_summary(
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

pub(in crate::modules) fn agentic_severity(value: &str) -> Severity {
    match value.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "ERROR" | "HIGH" => Severity::High,
        "WARNING" | "MEDIUM" => Severity::Medium,
        "INFO" | "LOW" => Severity::Low,
        _ => Severity::Unknown,
    }
}
