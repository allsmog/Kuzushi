//! Threat extraction for campaign planning.
//!
//! Accepts the persisted workspace threat model or a directory of subsystem
//! model documents and flattens their `threats[]` into planning rows. Key
//! variants mirror `module_recommender::threat_model_signals` (relatedCwe /
//! related_cwe / cwe) so both consumers read the same documents identically.

use serde_json::Value;

#[derive(Debug, Clone)]
pub(super) struct PlannedThreat {
    pub(super) id: String,
    pub(super) title: String,
    pub(super) description: String,
    pub(super) cwes: Vec<String>,
    pub(super) severity: String,
    /// Which document supplied the threat (`threat-model.json` or a file
    /// stem from `modelsDir`) — kept for provenance in plan rows.
    pub(super) source: String,
}

/// Flatten `threats[]` from every supplied document, in document order,
/// assigning positional fallback ids so every planned row stays addressable.
pub(super) fn planned_threats(documents: &[(String, Value)]) -> Vec<PlannedThreat> {
    let mut threats = Vec::new();
    for (source, document) in documents {
        collect_document_threats(source, document, &mut threats);
    }
    threats
}

fn collect_document_threats(source: &str, document: &Value, into: &mut Vec<PlannedThreat>) {
    let canonical = canonical_threat_document(document);
    let Some(rows) = canonical.get("threats").and_then(Value::as_array) else {
        return;
    };
    for (index, row) in rows.iter().enumerate() {
        into.push(planned_threat(source, row, into.len(), index));
    }
}

fn planned_threat(source: &str, row: &Value, position: usize, index: usize) -> PlannedThreat {
    let description = threat_string(row, &["description", "summary", "detail"]);
    PlannedThreat {
        id: threat_id(row, position),
        title: threat_title(row, &description, index),
        description,
        cwes: threat_cwes(row),
        severity: threat_string(row, &["severity", "risk", "priority"]).to_lowercase(),
        source: source.to_string(),
    }
}

fn threat_id(row: &Value, position: usize) -> String {
    let explicit = threat_string(row, &["id", "threatId", "threat_id"]);
    if explicit.is_empty() {
        return format!("threat-{}", position + 1);
    }
    explicit
}

fn threat_title(row: &Value, description: &str, index: usize) -> String {
    let explicit = threat_string(row, &["title", "name"]);
    if !explicit.is_empty() {
        return explicit;
    }
    let from_description = description.chars().take(72).collect::<String>();
    if from_description.is_empty() {
        return format!("Untitled threat {}", index + 1);
    }
    from_description
}

fn threat_string(row: &Value, keys: &[&str]) -> String {
    keys.iter()
        .filter_map(|key| row.get(*key))
        .filter_map(Value::as_str)
        .map(str::trim)
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn threat_cwes(row: &Value) -> Vec<String> {
    let Some(value) = related_cwe_value(row) else {
        return Vec::new();
    };
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|cwe| !cwe.is_empty())
            .map(str::to_string)
            .collect(),
        Value::String(single) if !single.trim().is_empty() => vec![single.trim().to_string()],
        _ => Vec::new(),
    }
}

fn related_cwe_value(row: &Value) -> Option<&Value> {
    row.get("relatedCwe")
        .or_else(|| row.get("related_cwe"))
        .or_else(|| row.get("cwe"))
}

fn canonical_threat_document(value: &Value) -> &Value {
    value
        .get("document")
        .or_else(|| value.pointer("/data/document"))
        .unwrap_or(value)
}
