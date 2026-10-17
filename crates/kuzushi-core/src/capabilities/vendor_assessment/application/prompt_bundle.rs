use serde_json::{json, Map, Value};
use std::path::Path;

pub(crate) fn build_prompt_bundle(scope: &Value) -> Vec<(String, String)> {
    let pretty_scope = serde_json::to_string_pretty(scope).unwrap_or_else(|_| "{}".to_string());
    vec![
        (
            "overview.md".to_string(),
            format!(
                "Assess this vendor scope for enterprise security risk. Ground all conclusions in attached document text when present.\n\nScope:\n{pretty_scope}"
            ),
        ),
        (
            "evidence-review.md".to_string(),
            "Extract concrete controls, gaps, integrations, data classes, and contractual commitments from the attached evidence.".to_string(),
        ),
        (
            "follow-up-questions.md".to_string(),
            "List high-signal follow-up questions for missing security evidence.".to_string(),
        ),
    ]
}

pub(crate) fn scope_has_text(scope: &Value) -> bool {
    scope
        .get("documents")
        .and_then(Value::as_array)
        .is_some_and(|documents| {
            documents.iter().any(|doc| {
                doc.get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.trim().is_empty())
            })
        })
}

pub(crate) fn build_report_base(run_id: &str, scope: &Value, run_root: &Path) -> Value {
    let docs = scope
        .get("documents")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({
        "runId": run_id,
        "overallRisk": "unassessed",
        "confidence": "unknown",
        "summary": "No model opinion stored.",
        "documents": docs,
        "domains": [],
        "mitigations": [],
        "artifacts": {
            "scopePath": run_root.join("scope.json").display().to_string(),
            "reportPath": run_root.join("report.md").display().to_string(),
            "reportJsonPath": run_root.join("report.json").display().to_string(),
            "promptsDir": run_root.join("prompts").display().to_string(),
        },
    })
}

pub(crate) fn merge_report_object(report: &mut Value, object: Map<String, Value>) {
    if let Value::Object(report_object) = report {
        merge_report_fields(report_object, &object);
    }
}

fn merge_report_fields(report_object: &mut Map<String, Value>, object: &Map<String, Value>) {
    for key in REPORT_FIELDS {
        insert_report_field(report_object, object, key);
    }
}

fn insert_report_field(
    report_object: &mut Map<String, Value>,
    object: &Map<String, Value>,
    key: &str,
) {
    if let Some(value) = object.get(key).cloned() {
        report_object.insert(key.to_string(), value);
    }
}

const REPORT_FIELDS: &[&str] = &[
    "overallRisk",
    "confidence",
    "summary",
    "domains",
    "mitigations",
    "documents",
];
