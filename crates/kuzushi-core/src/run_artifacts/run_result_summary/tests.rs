use super::*;
use crate::run_artifacts::{record_tool_run_complete, record_tool_run_started, ToolRunRecord};
use crate::run_lifecycle::SafeText;
use serde_json::{json, Value};

fn record_result<'a>(target: &'a Path, run_id: &'a str, output: &Value) -> ToolRunRecord<'a> {
    let record = ToolRunRecord {
        target,
        run_id,
        kind: "tool",
        tool: "fixture:run",
    };
    record_tool_run_started(record, &json!({}));
    record_tool_run_complete(record, output);
    record
}

fn correlated_reference(
    target: &Path,
    record: ToolRunRecord<'_>,
) -> (RunItemId, ArtifactReference) {
    let producer = RunItemId::new();
    let reference =
        crate::run_lifecycle::verified_result_artifact_reference(target, record.run_id, producer)
            .unwrap();
    (producer, reference)
}

#[test]
fn loads_bounded_semantic_fields_from_canonical_result() {
    let target = tempfile::tempdir().unwrap();
    let output = json!({
        "ok": true, "status": "partial", "summary": "no concrete evidence",
        "output": "Method: STRIDE\nThreats: 0", "warnings": ["choose another target"],
        "errors": [], "artifacts": [{
            "label": "normalized model", "path": "threat-model.json", "kind": "json"
        }]
    });
    let record = record_result(target.path(), "run-rich-result", &output);

    let summary = load_run_result_summary(target.path(), record.run_id)
        .unwrap()
        .unwrap();

    assert_eq!(summary.status, "partial");
    assert_eq!(summary.output_lines, ["Method: STRIDE", "Threats: 0"]);
    assert_eq!(summary.warnings, ["choose another target"]);
    assert_eq!(summary.artifacts[0].label, "normalized model");
}

#[test]
fn redacts_credentials_from_untrusted_result_text() {
    let safe = safe_bounded_line("Authorization: Bearer sk-secret");

    assert!(safe.contains("[REDACTED]"));
    assert!(!safe.contains("sk-secret"));
}

#[test]
fn escapes_and_bounds_untrusted_result_text() {
    let value = format!("status\u{001b}[31m {}", "x".repeat(MAX_LINE_CHARS));
    let safe = safe_bounded_line(&value);

    assert!(safe.contains("\\u{1b}"));
    assert!(!safe.contains('\u{001b}'));
    assert_eq!(safe.chars().count(), MAX_LINE_CHARS);
}

#[test]
fn operator_preview_prioritizes_decision_relevant_metrics() {
    let lines = [
        "tool partial",
        "Method: STRIDE",
        "Saved: preserved",
        "Threats: 0",
        "DFD: 1 node",
        "Findings: 0",
        "Cost: >=$0.0000 (incomplete)",
    ];
    let summary = RunResultSummary {
        run_id: "run".into(),
        tool: "tool".into(),
        status: "partial".into(),
        summary: "inadequate".into(),
        output_lines: lines.map(str::to_string).to_vec(),
        output_line_count: 7,
        warnings: vec![],
        warning_count: 0,
        errors: vec![],
        error_count: 0,
        artifacts: vec![],
        artifact_count: 0,
    };

    assert_eq!(
        summary.operator_output_preview(5),
        [
            "Threats: 0",
            "DFD: 1 node",
            "Findings: 0",
            "Cost: >=$0.0000 (incomplete)",
            "Saved: preserved"
        ]
    );
}

#[test]
fn correlated_loader_validates_the_exact_reference() {
    let target = tempfile::tempdir().unwrap();
    let output = json!({"ok": true, "status": "completed", "summary": "verified", "output": "Result: verified"});
    let record = record_result(target.path(), "run-correlated-result", &output);
    let (producer, reference) = correlated_reference(target.path(), record);

    let summary =
        load_correlated_run_result_summary(target.path(), record.run_id, producer, &reference)
            .unwrap();

    assert_eq!(summary.summary, "verified");
    assert_eq!(summary.output_line_count, 1);
}

#[test]
fn correlated_loader_rejects_digest_drift() {
    let target = tempfile::tempdir().unwrap();
    let record = record_result(target.path(), "run-drifted-result", &json!({"ok": true}));
    let (producer, reference) = correlated_reference(target.path(), record);
    let path = crate::run_artifacts::run_artifact_path(
        target.path(),
        record.run_id,
        reference.path.as_str(),
    );
    std::fs::write(path, br#"{"ok":true,"summary":"after"}"#).unwrap();

    let error =
        load_correlated_run_result_summary(target.path(), record.run_id, producer, &reference)
            .unwrap_err();

    assert!(error.to_string().contains("does not match"));
}

#[test]
fn correlated_loader_rejects_path_escape() {
    let target = tempfile::tempdir().unwrap();
    let record = record_result(target.path(), "run-unsafe-result", &json!({"ok": true}));
    let (producer, mut reference) = correlated_reference(target.path(), record);
    reference.path = SafeText::operator_visible("../result.json");

    let error =
        load_correlated_run_result_summary(target.path(), record.run_id, producer, &reference)
            .unwrap_err();

    assert!(error.to_string().contains("unsafe"));
}
