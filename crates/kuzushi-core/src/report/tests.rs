use super::*;
use crate::run_artifacts::{
    load_run_artifacts, write_run_artifact_json, write_run_failures, write_run_summary,
    RunLlmCallAudit, RunSummary,
};
use serde_json::json;
use std::fs;
use tempfile::tempdir;

#[test]
fn builds_markdown_report_from_latest_completed_non_report_run() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-source", "secret-scan:scan");
    write_run_summary(temp.path(), &source).unwrap();
    fs::write(
        temp.path().join(".kuzushi/runs/run-source/events.jsonl"),
        "{\"kind\":\"tool\"}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join(".kuzushi/runs/run-source/trace.jsonl"),
        "{\"kind\":\"reasoning\"}\n{\"kind\":\"done\"}\n",
    )
    .unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-source",
        "findings.json",
        "findings",
        &json!([{"title": "hardcoded token"}, {"title": "weak key"}]),
    )
    .unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-source",
        "threat-model.json",
        "threat model",
        &json!({
            "methodology": "stride",
            "dfd": {
                "nodes": [{"id": "app"}, {"id": "data-store"}],
                "flows": [{"id": "flow-data-store"}],
                "trustBoundaries": [{"id": "tb-public-http"}]
            },
            "threats": [
                {"id": "T-001", "relatedCwe": ["CWE-20", "CWE-918"]},
                {"id": "T-002", "relatedCwe": ["CWE-20"]}
            ]
        }),
    )
    .unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-source",
        "attack-surface.json",
        "attack surface",
        &json!({
            "summary": {
                "surfaceCount": 4,
                "highRisk": 2,
                "maxRiskScore": 98,
                "byRiskTier": {"critical": 1, "high": 1, "medium": 2}
            }
        }),
    )
    .unwrap();
    fs::write(
        temp.path()
            .join(".kuzushi/runs/run-source/report.sarif"),
        r#"{"version":"2.1.0","runs":[]}"#,
    )
    .unwrap();
    let report_run = RunSummary::running(
        "zz-report",
        "tool",
        Some("report:build".to_string()),
        temp.path().display().to_string(),
    );
    write_run_summary(temp.path(), &report_run).unwrap();

    let report = build_run_report(temp.path(), None).unwrap();

    assert_eq!(report.source_run_id, "run-source");
    assert_eq!(report.source_tool.as_deref(), Some("secret-scan:scan"));
    assert!(report.report_markdown.contains("# Kuzushi Run Report"));
    assert!(report.report_markdown.contains("run.json: present"));
    assert!(report.report_markdown.contains("artifacts.json: present"));
    assert!(report.report_markdown.contains(
        "attack-surface.json: present - 4 surface(s), 2 high risk, max 98, tiers critical=1, high=1, medium=2"
    ));
    assert!(report.report_markdown.contains(
        "threat-model.json: present - methodology stride, 2 threat(s), DFD nodes=2, flows=1, boundaries=1, CWEs CWE-20=2, CWE-918=1"
    ));
    assert!(report.report_markdown.contains("findings.json: present"));
    assert!(report.report_markdown.contains("events.jsonl: present - 1 line(s)"));
    assert!(report.report_markdown.contains("trace.jsonl: present - 2 line(s)"));
    assert!(report.report_markdown.contains("report.md: present - generated report"));
    assert!(report.report_markdown.contains("report.sarif: present"));
    assert!(!report.report_markdown.contains("## Failure Handoff"));
    let report_body = fs::read_to_string(temp.path().join(".kuzushi/runs/run-source/report.md"))
        .unwrap();
    assert!(report_body.contains("secret-scan:scan"));
    let manifest = load_run_artifacts(temp.path(), "run-source").unwrap();
    assert!(manifest
        .iter()
        .any(|artifact| artifact.path.ends_with("report.md")));
}

#[test]
fn tool_json_exposes_standard_envelope_and_report_markdown() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-source", "dep-hygiene:check");
    write_run_summary(temp.path(), &source).unwrap();
    fs::remove_file(temp.path().join(".kuzushi/runs/run-source/findings.json")).unwrap();

    let output = build_run_report(temp.path(), Some("run-source"))
        .unwrap()
        .to_tool_json();

    assert_eq!(output["ok"], json!(true));
    assert_eq!(output["status"], json!("completed"));
    assert!(output["reportMarkdown"].as_str().unwrap().contains("run-source"));
    assert_eq!(output["artifacts"][0]["label"], json!("report"));
    assert_eq!(output["data"]["sourceRunId"], json!("run-source"));
    assert!(output["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning == "canonical artifact findings.json is missing"));
}

#[test]
fn default_source_uses_run_time_not_lexical_run_id() {
    let temp = tempdir().unwrap();
    let mut older = completed_summary(temp.path(), "zz-old", "secret-scan:scan");
    older.started_at_unix = 1;
    older.completed_at_unix = Some(1);
    let mut newer = completed_summary(temp.path(), "aa-new", "dep-hygiene:check");
    newer.started_at_unix = 2;
    newer.completed_at_unix = Some(2);
    write_run_summary(temp.path(), &older).unwrap();
    write_run_summary(temp.path(), &newer).unwrap();

    let report = build_run_report(temp.path(), None).unwrap();

    assert_eq!(report.source_run_id, "aa-new");
}

#[test]
fn report_markdown_surfaces_llm_audit_metadata_from_run_json() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-llm", "agentic-sast:scan").with_llm_calls(vec![
        RunLlmCallAudit {
            n: 7,
            kind: "reasoning".to_string(),
            verb: Some("query".to_string()),
            model: "openai:gpt-test".to_string(),
            provider: "openai".to_string(),
            prompt_hash: "fnv1a64:abc123".to_string(),
            latency_ms: Some(42),
            cost_usd: Some(0.0042),
        },
    ]);
    write_run_summary(temp.path(), &source).unwrap();

    let report = build_run_report(temp.path(), Some("run-llm")).unwrap();

    assert!(report.report_markdown.contains("## LLM Calls"));
    assert!(report.report_markdown.contains("openai:gpt-test"));
    assert!(report.report_markdown.contains("prompt=fnv1a64:abc123"));
    assert!(report.report_markdown.contains("cost=0.004200"));
}

#[test]
fn report_markdown_surfaces_failure_handoff_bounds() {
    let temp = tempdir().unwrap();
    let source =
        RunSummary::running("run-failed", "tool", Some("semgrep:scan".to_string()), "target")
            .failed("semgrep binary missing");
    write_run_summary(temp.path(), &source).unwrap();
    let result = write_run_artifact_json(
        temp.path(),
        "run-failed",
        "result.json",
        "result",
        &json!({"ok": false, "status": "failed"}),
    )
    .unwrap();
    write_run_failures(
        temp.path(),
        "run-failed",
        "semgrep:scan",
        "failed",
        "semgrep binary missing",
        &[result],
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-failed")).unwrap();
    let output = report.to_tool_json();

    assert!(report.report_markdown.contains("## Failure Handoff"));
    assert!(report.report_markdown.contains("Failed Stage: semgrep:scan"));
    assert!(report.report_markdown.contains("semgrep binary missing"));
    assert!(report.report_markdown.contains("Available Artifacts"));
    assert!(report.report_markdown.contains("result.json"));
    assert!(report.report_markdown.contains("artifact-review-only"));
    assert!(report.report_markdown.contains("Fallback Prompt"));
    assert!(report.report_markdown.contains("Forbidden Claims"));
    assert!(report.report_markdown.contains("exploit proven"));
    assert!(report.report_markdown.contains("verified claim"));
    assert!(report.report_markdown.contains("false positive verdict"));
    assert_eq!(report.failure_handoffs[0].failed_stage, "semgrep:scan");
    assert!(report.failure_handoffs[0]
        .fallback_prompt
        .contains("semgrep binary missing"));
    assert_eq!(
        output["data"]["failureHandoffs"][0]["allowedProofLevel"],
        json!("artifact-review-only; runtime verification did not run")
    );
    assert!(output["data"]["failureHandoffs"][0]["artifactsAvailable"][0]["path"]
        .as_str()
        .is_some_and(|path| path.ends_with("result.json")));
    assert!(output["data"]["failureHandoffs"][0]["fallbackPrompt"]
        .as_str()
        .is_some_and(|prompt| prompt.contains("semgrep binary missing")));
}

fn completed_summary(target: &std::path::Path, run_id: &str, tool: &str) -> RunSummary {
    RunSummary::running(
        run_id,
        "tool",
        Some(tool.to_string()),
        target.display().to_string(),
    )
    .complete()
    .with_findings(Some(2))
}
