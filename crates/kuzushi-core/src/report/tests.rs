use super::*;
use crate::run_artifacts::{
    load_run_artifacts, run_dir, write_run_artifact_json, write_run_failures, write_run_summary,
    RunEnvFingerprint, RunLlmCallAudit, RunSummary, RunTargetGitMetadata,
};
use serde_json::json;
use std::fs;
use tempfile::tempdir;

#[test]
fn builds_markdown_report_from_latest_completed_non_report_run() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-source", "secret-scan:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let source_run_dir = run_dir(temp.path(), "run-source");
    fs::write(source_run_dir.join("events.jsonl"), "{\"kind\":\"tool\"}\n").unwrap();
    fs::write(
        source_run_dir.join("trace.jsonl"),
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
                "byRiskTier": {"critical": 1, "high": 1, "medium": 2},
                "byKind": {"file_upload_parse_path": 1, "http_route": 3}
            }
        }),
    )
    .unwrap();
    fs::write(
        source_run_dir.join("report.sarif"),
        r#"{"version":"2.1.0","runs":[{"results":[{"ruleId":"secret","level":"warning","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.ts"}}},{"physicalLocation":{"artifactLocation":{"uri":"src/config.ts"}}}]},{"ruleId":"secret","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/app.ts"}}}]}]}]}"#,
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
    assert!(report
        .report_markdown
        .contains("context.json: present - No context snapshot was recorded for this run."));
    assert!(report.report_markdown.contains(
        "attack-surface.json: present - 4 surface(s), 2 high risk, max 98, tiers critical=1, high=1, medium=2, kinds file_upload_parse_path=1, http_route=3"
    ));
    assert!(report.report_markdown.contains(
        "threat-model.json: present - methodology stride, 2 threat(s), DFD nodes=2, flows=1, boundaries=1, CWEs CWE-20=2, CWE-918=1"
    ));
    assert!(report.report_markdown.contains("findings.json: present"));
    assert!(report.report_markdown.contains("events.jsonl: present - 1 line(s)"));
    assert!(report.report_markdown.contains("trace.jsonl: present - 2 line(s)"));
    assert!(report.report_markdown.contains("report.md: present - generated report"));
    assert!(report
        .report_markdown
        .contains("report.sarif: present - SARIF report, 1 run(s), 2 result(s), levels error=1, warning=1, rules secret=2, files src/app.ts=2, src/config.ts=1"));
    assert!(!report.report_markdown.contains("## Failure Handoff"));
    let report_body = fs::read_to_string(source_run_dir.join("report.md")).unwrap();
    assert!(report_body.contains("secret-scan:scan"));
    let manifest = load_run_artifacts(temp.path(), "run-source").unwrap();
    assert!(manifest
        .iter()
        .any(|artifact| artifact.path.ends_with("report.md")));
}

#[test]
fn report_marks_malformed_canonical_json_as_present() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-bad-context", "context:build");
    write_run_summary(temp.path(), &source).unwrap();
    fs::write(
        run_dir(temp.path(), "run-bad-context").join("context.json"),
        "{not-json",
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-bad-context")).unwrap();

    assert!(report
        .report_markdown
        .contains("context.json: present - malformed JSON"));
    let context = report
        .canonical_artifacts
        .iter()
        .find(|artifact| artifact.file == "context.json")
        .unwrap();
    assert!(context.present);
    assert!(context.summary.contains("malformed JSON"));
}

#[test]
fn report_marks_malformed_tool_result_json_as_present() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-bad-result", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    fs::write(
        run_dir(temp.path(), "run-bad-result").join("result.json"),
        "{not-json",
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-bad-result")).unwrap();

    assert!(report
        .report_markdown
        .contains("result.json: present - malformed JSON"));
    let result = report
        .canonical_artifacts
        .iter()
        .find(|artifact| artifact.file == "result.json")
        .unwrap();
    assert!(result.present);
    assert!(result.summary.contains("malformed JSON"));
}

#[test]
fn report_marks_malformed_sarif_as_present() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-bad-sarif", "codeql:scan");
    write_run_summary(temp.path(), &source).unwrap();
    fs::write(
        run_dir(temp.path(), "run-bad-sarif").join("report.sarif"),
        "{not-json",
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-bad-sarif")).unwrap();

    assert!(report
        .report_markdown
        .contains("report.sarif: present - malformed SARIF JSON"));
    let sarif = report
        .canonical_artifacts
        .iter()
        .find(|artifact| artifact.file == "report.sarif")
        .unwrap();
    assert!(sarif.present);
    assert!(sarif.summary.contains("malformed SARIF JSON"));
}

#[test]
fn report_marks_sarif_missing_runs_as_malformed() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-sarif-no-runs", "codeql:scan");
    write_run_summary(temp.path(), &source).unwrap();
    fs::write(
        run_dir(temp.path(), "run-sarif-no-runs").join("report.sarif"),
        r#"{"version":"2.1.0","runsMissing":[]}"#,
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-sarif-no-runs")).unwrap();

    assert!(report
        .report_markdown
        .contains("report.sarif: present - malformed SARIF: missing runs array"));
    let sarif = report
        .canonical_artifacts
        .iter()
        .find(|artifact| artifact.file == "report.sarif")
        .unwrap();
    assert!(sarif.present);
    assert_eq!(sarif.summary, "malformed SARIF: missing runs array");
}

#[test]
fn report_summarizes_run_event_and_trace_jsonl_shapes() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-jsonl", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-jsonl");
    fs::write(
        dir.join("events.jsonl"),
        [
            r#"{"n":1,"kind":"tool","status":"started","message":"started","atUnix":1,"tool":"agentic-sast:scan"}"#,
            r#"{"n":2,"kind":"tool","status":"completed","message":"done","at_unix":6,"tool":"agentic-sast:scan","artifact":{"label":"findings","path":"findings.json","kind":"json"}}"#,
        ]
        .join("\n"),
    )
    .unwrap();
    fs::write(
        dir.join("trace.jsonl"),
        [
            r#"{"n":1,"kind":"reasoning","label":"plan","severity":"info","verb":"query","model":"openai:gpt-test","provider":"openai","latency_ms":40,"parent_step":0,"cost_usd":0.01}"#,
            r#"{"n":2,"kind":"tool-progress","label":"scan","severity":"warn","verb":"scan","latencyMs":2,"parentStep":0}"#,
            r#"{"n":3,"kind":"done","label":"complete"}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-jsonl")).unwrap();

    assert!(report.report_markdown.contains(
        "events.jsonl: present - 2 event(s), kinds tool=2, status completed=1, started=1, tools agentic-sast:scan, span 5s, artifacts 1"
    ));
    assert!(report.report_markdown.contains(
        "trace.jsonl: present - 3 step(s), kinds done=1, reasoning=1, tool-progress=1, severity info=1, warn=1, verbs query, scan, child steps 2, llm calls 1, latency 42ms, cost $0.010000"
    ));
}

#[test]
fn report_summarizes_malformed_jsonl_lines() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-bad-jsonl", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-bad-jsonl");
    fs::write(
        dir.join("events.jsonl"),
        [
            r#"{"n":1,"kind":"tool","status":"started","message":"started","tool":"sast:scan"}"#,
            "{not-json",
        ]
        .join("\n"),
    )
    .unwrap();
    fs::write(dir.join("trace.jsonl"), "{not-json\n").unwrap();

    let report = build_run_report(temp.path(), Some("run-bad-jsonl")).unwrap();

    assert!(report.report_markdown.contains(
        "events.jsonl: present - 1 event(s), kinds tool=1, status started=1, tools sast:scan, malformed line(s) 1"
    ));
    assert!(report
        .report_markdown
        .contains("trace.jsonl: present - malformed JSONL line(s) 1"));
}

#[test]
fn report_summarizes_non_object_jsonl_rows_as_malformed() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-non-object-jsonl", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-non-object-jsonl");
    fs::write(
        dir.join("events.jsonl"),
        [
            r#"{"n":1,"kind":"tool","status":"started","message":"started","tool":"sast:scan"}"#,
            "[]",
        ]
        .join("\n"),
    )
    .unwrap();
    fs::write(
        dir.join("trace.jsonl"),
        [
            r#"{"n":1,"kind":"reasoning","label":"query"}"#,
            "[]",
        ]
        .join("\n"),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-non-object-jsonl")).unwrap();

    assert!(report.report_markdown.contains(
        "events.jsonl: present - 1 event(s), kinds tool=1, status started=1, tools sast:scan, malformed line(s) 1"
    ));
    assert!(report.report_markdown.contains(
        "trace.jsonl: present - 1 step(s), kinds reasoning=1, malformed line(s) 1"
    ));
}

#[test]
fn report_surfaces_non_file_jsonl_artifacts_as_present_malformed() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-non-file-jsonl", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-non-file-jsonl");
    fs::remove_file(dir.join("events.jsonl")).unwrap();
    fs::remove_file(dir.join("trace.jsonl")).unwrap();
    fs::create_dir(dir.join("events.jsonl")).unwrap();
    fs::create_dir(dir.join("trace.jsonl")).unwrap();

    let report = build_run_report(temp.path(), Some("run-non-file-jsonl")).unwrap();

    assert!(report
        .report_markdown
        .contains("events.jsonl: present - text artifact is not a file"));
    assert!(report
        .report_markdown
        .contains("trace.jsonl: present - text artifact is not a file"));
    assert!(!report
        .report_markdown
        .contains("canonical artifact events.jsonl is missing"));
    assert!(!report
        .report_markdown
        .contains("canonical artifact trace.jsonl is missing"));
}

#[test]
fn report_surfaces_non_file_json_artifacts_as_present_malformed() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-non-file-json", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-non-file-json");
    fs::remove_file(dir.join("context.json")).unwrap();
    fs::create_dir(dir.join("context.json")).unwrap();

    let report = build_run_report(temp.path(), Some("run-non-file-json")).unwrap();

    assert!(report
        .report_markdown
        .contains("context.json: present - JSON artifact is not a file"));
    assert!(!report
        .report_markdown
        .contains("canonical artifact context.json is missing"));
}

#[test]
fn report_marks_non_object_canonical_json_as_malformed() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-non-object-context", "context:build");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-non-object-context");
    fs::write(dir.join("context.json"), "[]").unwrap();

    let report = build_run_report(temp.path(), Some("run-non-object-context")).unwrap();

    assert!(report
        .report_markdown
        .contains("context.json: present - malformed JSON: expected object"));
    let context = report
        .canonical_artifacts
        .iter()
        .find(|artifact| artifact.file == "context.json")
        .unwrap();
    assert!(context.present);
    assert_eq!(context.summary, "malformed JSON: expected object");
}

#[test]
fn report_summarizes_event_tool_name_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-event-aliases", "agent:ask");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-event-aliases");
    fs::write(
        dir.join("events.jsonl"),
        [
            r#"{"n":1,"kind":"tool","status":"started","message":"ask","atUnix":1,"toolName":"agent:ask"}"#,
            r#"{"n":2,"kind":"tool","status":"completed","message":"scan","at_unix":2,"tool_name":"sast:scan"}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-event-aliases")).unwrap();

    assert!(report.report_markdown.contains(
        "events.jsonl: present - 2 event(s), kinds tool=2, status completed=1, started=1, tools agent:ask, sast:scan"
    ));
}

#[test]
fn report_counts_event_artifact_path_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-event-artifact-aliases", "sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-event-artifact-aliases");
    fs::write(
        dir.join("events.jsonl"),
        [
            r#"{"n":1,"kind":"tool","status":"started","message":"scan","atUnix":1,"tool":"sast:scan","artifactPath":"input.json"}"#,
            r#"{"n":2,"kind":"tool","status":"completed","message":"done","at_unix":2,"tool":"sast:scan","artifact_path":"result.json"}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-event-artifact-aliases")).unwrap();

    assert!(report.report_markdown.contains(
        "events.jsonl: present - 2 event(s), kinds tool=2, status completed=1, started=1, tools sast:scan, span 1s, artifacts 2"
    ));
}

#[test]
fn report_ignores_empty_event_artifact_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-event-empty-artifacts", "sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-event-empty-artifacts");
    fs::write(
        dir.join("events.jsonl"),
        [
            r#"{"n":1,"kind":"tool","status":"started","message":"scan","atUnix":1,"tool":"sast:scan","artifact":null}"#,
            r#"{"n":2,"kind":"tool","status":"completed","message":"done","atUnix":2,"tool":"sast:scan","artifactPath":"  "}"#,
            r#"{"n":3,"kind":"tool","status":"completed","message":"result","atUnix":3,"tool":"sast:scan","artifact_path":"result.json"}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-event-empty-artifacts")).unwrap();

    assert!(report.report_markdown.contains(
        "events.jsonl: present - 3 event(s), kinds tool=3, status completed=2, started=1, tools sast:scan, span 2s, artifacts 1"
    ));
}

#[test]
fn report_summarizes_camel_case_trace_cost_alias() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-trace-aliases", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-trace-aliases");
    fs::write(
        dir.join("trace.jsonl"),
        [
            r#"{"n":1,"kind":"reasoning","label":"plan","model":"openai:gpt-test","provider":"openai","costUsd":0.02}"#,
            r#"{"n":2,"kind":"done","label":"complete","cost_usd":0.01}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-trace-aliases")).unwrap();

    assert!(report.report_markdown.contains(
        "trace.jsonl: present - 2 step(s), kinds done=1, reasoning=1, llm calls 1, cost $0.030000"
    ));
}

#[test]
fn report_counts_prompt_hash_only_trace_llm_calls() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-trace-prompt-hash", "triage:run");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-trace-prompt-hash");
    fs::write(
        dir.join("trace.jsonl"),
        [
            r#"{"n":1,"kind":"reasoning","label":"plan","promptHash":"fnv1a64:abc"}"#,
            r#"{"n":2,"kind":"reasoning","label":"review","prompt_hash":"fnv1a64:def"}"#,
            r#"{"n":3,"kind":"done","label":"complete"}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-trace-prompt-hash")).unwrap();

    assert!(report.report_markdown.contains(
        "trace.jsonl: present - 3 step(s), kinds done=1, reasoning=2, llm calls 2"
    ));
}

#[test]
fn report_ignores_empty_trace_llm_metadata() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-trace-empty-llm", "triage:run");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-trace-empty-llm");
    fs::write(
        dir.join("trace.jsonl"),
        [
            r#"{"n":1,"kind":"reasoning","label":"plan","promptHash":"  "}"#,
            r#"{"n":2,"kind":"reasoning","label":"review","provider":""}"#,
            r#"{"n":3,"kind":"done","label":"complete","prompt_hash":"fnv1a64:def"}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-trace-empty-llm")).unwrap();

    assert!(report.report_markdown.contains(
        "trace.jsonl: present - 3 step(s), kinds done=1, reasoning=2, llm calls 1"
    ));
}

#[test]
fn report_summarizes_trace_module_id_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-trace-modules", "triage:run");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-trace-modules");
    fs::write(
        dir.join("trace.jsonl"),
        [
            r#"{"n":1,"kind":"tool","label":"triage started","module_id":"triage"}"#,
            r#"{"n":2,"kind":"reasoning","label":"verify evidence","moduleId":"verify"}"#,
            r#"{"n":3,"kind":"done","label":"triage done","module_id":"triage"}"#,
        ]
        .join("\n"),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-trace-modules")).unwrap();

    assert!(report.report_markdown.contains(
        "trace.jsonl: present - 3 step(s), kinds done=1, reasoning=1, tool=1, modules triage, verify"
    ));
}

#[test]
fn report_summarizes_canonical_attack_surface_total_shape() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-attack-surface", "context:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-attack-surface",
        "attack-surface.json",
        "attack surface",
        &json!({
            "summary": {
                "total": 5,
                "highRisk": 1,
                "maxRiskScore": 90,
                "byRiskTier": {"critical": 1, "low": 3}
            },
            "surfaces": [
                {"boundary": "public", "framework": "Django", "kind": "http_route", "language": "Python", "method": "GET"},
                {"boundary": "public", "framework": "Spring", "kind": "file_upload_parse_path", "language": "Java", "method": "POST"},
                {"boundary": "admin", "framework": "Rails", "kind": "http_route", "language": "Ruby", "method": "POST"},
                {"boundary": "public", "framework": "Next.js", "kind": "http_route", "language": "TypeScript", "method": "GET"},
                {"boundary": "internal", "framework": "Spring", "kind": "rpc_handler", "language": "Java", "method": "ANY"}
            ]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-attack-surface")).unwrap();

    assert!(report.report_markdown.contains(
        "attack-surface.json: present - 5 surface(s), 1 high risk, max 90, tiers critical=1, low=3, kinds file_upload_parse_path=1, http_route=3, rpc_handler=1, frameworks Django=1, Next.js=1, Rails=1, Spring=2, languages Java=2, Python=1, Ruby=1, TypeScript=1, methods ANY=1, GET=2, POST=2, boundaries admin=1, internal=1, public=3"
    ));
}

#[test]
fn report_summarizes_attack_surface_snake_case_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-attack-surface-aliases", "context:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-attack-surface-aliases",
        "attack-surface.json",
        "attack surface",
        &json!({
            "summary": {
                "surface_count": 3,
                "high_risk": 1,
                "max_risk_score": 82,
                "by_risk_tier": {"high": 1, "low": 2},
                "by_kind": {"file_upload_parse_path": 1, "http_route": 2}
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-attack-surface-aliases")).unwrap();

    assert!(report.report_markdown.contains(
        "attack-surface.json: present - 3 surface(s), 1 high risk, max 82, tiers high=1, low=2, kinds file_upload_parse_path=1, http_route=2"
    ));
}

#[test]
fn report_summarizes_root_level_attack_surface_snapshot_fields() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-attack-surface-root", "context:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-attack-surface-root",
        "attack-surface.json",
        "attack surface",
        &json!({
            "surface_count": 2,
            "high_risk": 1,
            "max_risk_score": 88,
            "by_risk_tier": {"high": 1, "medium": 1},
            "entries": [
                {"framework": "FastAPI", "kind": "http_route"},
                {"framework": "Tonic", "kind": "rpc_handler"}
            ]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-attack-surface-root")).unwrap();

    assert!(report.report_markdown.contains(
        "attack-surface.json: present - 2 surface(s), 1 high risk, max 88, tiers high=1, medium=1, kinds http_route=1, rpc_handler=1, frameworks FastAPI=1, Tonic=1"
    ));
}

#[test]
fn report_summarizes_attack_surface_array_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-attack-surface-array-aliases", "context:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-attack-surface-array-aliases",
        "attack-surface.json",
        "attack surface",
        &json!({
            "summary": {
                "surface_count": 2,
                "high_risk": 0,
                "by_kind": {}
            },
            "attack_surfaces": [
                {"framework": "Laravel", "kind": "file_upload_parse_path"},
                {"framework": "Tonic", "kind": "rpc_handler"}
            ]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-attack-surface-array-aliases")).unwrap();

    assert!(report.report_markdown.contains(
        "attack-surface.json: present - 2 surface(s), 0 high risk, kinds file_upload_parse_path=1, rpc_handler=1, frameworks Laravel=1, Tonic=1"
    ));
}

#[test]
fn report_derives_attack_surface_risk_from_surfaces() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-attack-surface-risk", "context:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-attack-surface-risk",
        "attack-surface.json",
        "attack surface",
        &json!({
            "surfaces": [
                {
                    "framework": "Express",
                    "kind": "http_route",
                    "method": "POST",
                    "boundary": "public",
                    "risk": {"tier": "critical", "score": 96}
                },
                {
                    "framework": "Tonic",
                    "kind": "rpc_handler",
                    "method": "ANY",
                    "boundary": "internal",
                    "risk": {"tier": "high", "score": 82}
                },
                {
                    "framework": "Rails",
                    "kind": "background_job",
                    "boundary": "async_job",
                    "risk": {"tier": "low", "score": 25}
                }
            ]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-attack-surface-risk")).unwrap();

    assert!(report.report_markdown.contains(
        "attack-surface.json: present - 3 surface(s), 2 high risk, max 96, tiers critical=1, high=1, low=1, kinds background_job=1, http_route=1, rpc_handler=1, frameworks Express=1, Rails=1, Tonic=1, methods ANY=1, POST=1, boundaries async_job=1, internal=1, public=1"
    ));
}

#[test]
fn report_summarizes_canonical_context_snapshot_shape() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-context", "context:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-context",
        "context.json",
        "context snapshot",
        &json!({
            "filesIndexed": 42,
            "fileIndex": {
                "tree": [{"path": "src/main.ts"}],
                "totalFiles": 42,
                "truncated": true,
                "patternMatches": {
                    "package-manifests": [{"path": "package.json"}],
                    "route-files": 2
                }
            },
            "repoContext": {
                "languages": ["TypeScript", "Rust"],
                "frameworks": ["Django", "Spring", "Rails", "Laravel", "Next.js"]
            },
            "appModel": {
                "routes": [
                    {"id": "route-users", "method": "GET", "framework": "Next.js"},
                    {"id": "route-import", "method": "POST", "framework": "Next.js"}
                ],
                "outboundClients": [{"id": "stripe"}],
                "serviceBoundaries": [{"id": "payments"}],
                "dataStores": [{"id": "postgres"}],
                "backgroundJobs": [{"id": "sync"}]
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-context")).unwrap();

    assert!(report.report_markdown.contains(
        "context.json: present - 42 file(s), file index truncated, pattern matches 3, languages TypeScript, Rust, frameworks Django, Spring, Rails, Laravel, Next.js, 2 route(s), 1 outbound client(s), 1 service boundary(ies), 1 data store(s), 1 background job(s), methods GET=1, POST=1, route frameworks Next.js=2"
    ));
}

#[test]
fn report_summarizes_snake_case_context_snapshot_shape() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-context-snake", "context:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-context-snake",
        "context.json",
        "context snapshot",
        &json!({
            "files_indexed": 7,
            "file_index": {
                "tree": [{"path": "app.py"}],
                "total_files": 7,
                "truncated": true
            },
            "repo_context": {
                "languages": ["Python"],
                "frameworks": ["Django"]
            },
            "app_model": {
                "routes": [{"id": "route-admin"}],
                "outbound_clients": [{"id": "stripe"}],
                "service_boundaries": [{"id": "payments"}],
                "data_stores": [{"id": "postgres"}],
                "background_jobs": [{"id": "sync"}]
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-context-snake")).unwrap();

    assert!(report.report_markdown.contains(
        "context.json: present - 7 file(s), file index truncated, languages Python, frameworks Django, 1 route(s), 1 outbound client(s), 1 service boundary(ies), 1 data store(s), 1 background job(s)"
    ));
}

#[test]
fn report_summarizes_enveloped_context_snapshot_shape() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-context-envelope", "context:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-context-envelope",
        "context.json",
        "context snapshot",
        &json!({
            "status": "completed",
            "data": {
                "context": {
                    "filesIndexed": 3,
                    "fileIndex": {"totalFiles": 3},
                    "repoContext": {
                        "languages": ["Go"],
                        "frameworks": ["Tonic"]
                    },
                    "appModel": {
                        "routes": [{"id": "route-rpc"}],
                        "outboundClients": [{"id": "billing"}]
                    }
                }
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-context-envelope")).unwrap();

    assert!(report.report_markdown.contains(
        "context.json: present - 3 file(s), languages Go, frameworks Tonic, 1 route(s), 1 outbound client(s)"
    ));
}

#[test]
fn report_summarizes_run_metadata_and_artifact_manifest() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-metadata", "agentic-sast:scan")
        .with_model(Some("openai:gpt-test".to_string()))
        .with_config_hash(Some("sha256:cfg".to_string()))
        .with_cli_args(vec![
            "kuzushi".to_string(),
            "run".to_string(),
            "agentic-sast:scan".to_string(),
        ])
        .with_env_fingerprint(vec![RunEnvFingerprint {
            key: "KUZUSHI_TEST".to_string(),
            fingerprint: "sha256:env".to_string(),
        }])
        .with_target_git(Some(RunTargetGitMetadata {
            sha: "abcdef123456".to_string(),
            branch: Some("main".to_string()),
            dirty: false,
        }))
        .with_cost(Some(0.125))
        .with_llm_calls(vec![RunLlmCallAudit {
            n: 1,
            kind: "reasoning".to_string(),
            verb: Some("query".to_string()),
            model: "openai:gpt-test".to_string(),
            provider: "openai".to_string(),
            prompt_hash: "fnv1a64:abc123".to_string(),
            latency_ms: Some(10),
            cost_usd: Some(0.125),
        }]);
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-metadata",
        "evidence.json",
        "evidence",
        &json!({"ok": true}),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-metadata")).unwrap();

    assert!(
        report.report_markdown.contains(
            "run.json: present - run run-metadata, status completed, duration 0s, tool agentic-sast:scan, findings 2, model openai:gpt-test, config sha256:cfg, llm calls 1, cost $0.125000, cli args 3, env 1, target git abcdef123456 clean"
        ),
        "{}",
        report.report_markdown
    );
    assert!(report.report_markdown.contains(
        "artifacts.json: present - 13 artifact(s), kinds json=10, jsonl=2, markdown=1, canonical 12"
    ));
    assert!(report
        .report_markdown
        .contains("labels run metadata, run events, runtime trace, context snapshot"));
}

#[test]
fn report_summarizes_snake_case_run_metadata_and_manifest() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-metadata-snake", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-metadata-snake");
    fs::write(
        dir.join("run.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-metadata-snake",
            "kind": "tool",
            "status": "completed",
            "tool": "agentic-sast:scan",
            "target": "target",
            "started_at_unix": 1,
            "completed_at_unix": 9,
            "findings": 3,
            "model": "openai:gpt-test",
            "config_hash": "sha256:def",
            "house_rules": [{"module": "triage", "path": ".kuzushi/house-rules/triage.md", "sha256": "sha256:rule"}],
            "prompt_overrides": [{"module": "triage", "verb": "run", "path": ".kuzushi/prompts/triage/run.md", "sha256": "sha256:prompt"}],
            "scan_args": ["--target", "target"],
            "loaded_module_specifiers": ["builtin:triage"],
            "env_fingerprint": [{"key": "KUZUSHI_TEST", "fingerprint": "sha256:env"}],
            "target_git": {"sha": "abcdef123456", "branch": "main", "dirty": true},
            "llm_calls": [{
                "n": 1,
                "kind": "reasoning",
                "model": "openai:gpt-test",
                "provider": "openai",
                "prompt_hash": "fnv1a64:abc123"
            }],
            "cost_usd": 0.5
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-metadata-snake",
            "artifacts": [
                {"label": "run metadata", "path": "run.json", "kind": "json"},
                {"label": "run events", "path": "events.jsonl", "kind": "jsonl"},
                {"label": "runtime trace", "path": "trace.jsonl", "kind": "jsonl"}
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-metadata-snake")).unwrap();

    assert!(
        report.report_markdown.contains(
            "run.json: present - run run-metadata-snake, status completed, duration 8s, tool agentic-sast:scan, findings 3, model openai:gpt-test, config sha256:def, llm calls 1, cost $0.500000, house rules 1, prompt overrides 1, scan args 2, module specifiers 1, env 1, target git abcdef123456 dirty"
        ),
        "{}",
        report.report_markdown
    );
    assert!(report.report_markdown.contains(
        "artifacts.json: present - 3 artifact(s), kinds json=1, jsonl=2, canonical 3, labels run metadata, run events, runtime trace"
    ));
}

#[test]
fn report_summarizes_artifact_manifest_field_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-manifest-aliases", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-manifest-aliases");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-manifest-aliases",
            "artifacts": [
                {"name": "run metadata", "filePath": "run.json", "type": "json"},
                {"title": "runtime trace", "report_json_path": "trace.jsonl", "type": "jsonl"},
                {"label": "prompt overrides", "prompts_dir": ".kuzushi/prompts", "type": "directory"},
                {"label": "SARIF report", "reportPath": "report.sarif", "type": "sarif"},
                {"label": "tool input", "path": "input.json", "type": "json"},
                {"label": "tool result", "path": "result.json", "type": "json"}
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-manifest-aliases")).unwrap();

    assert!(
        report.report_markdown.contains(
            "artifacts.json: present - 6 artifact(s), kinds directory=1, json=3, jsonl=1, sarif=1, canonical 2, optional SARIF report, tool inputs tool input, tool results tool result, aliases labels=2, paths=4, kinds=6, labels run metadata, runtime trace, prompt overrides, SARIF report"
        ),
        "{}",
        report.report_markdown
    );
    assert!(report
        .report_markdown
        .contains("- runtime trace (jsonl) - trace.jsonl"));
    assert!(report
        .report_markdown
        .contains("- prompt overrides (directory) - .kuzushi/prompts"));
    assert_eq!(report.declared_artifacts[1].label, "runtime trace");
    assert_eq!(report.declared_artifacts[1].path, "trace.jsonl");
    assert_eq!(report.declared_artifacts[1].kind, "jsonl");
    assert_eq!(report.declared_artifacts[3].label, "SARIF report");
    assert_eq!(report.declared_artifacts[3].path, "report.sarif");
    assert_eq!(report.declared_artifacts[3].kind, "sarif");
    assert_eq!(report.declared_artifacts[4].label, "tool input");
    assert_eq!(report.declared_artifacts[4].path, "input.json");
    assert_eq!(report.declared_artifacts[4].kind, "json");
    assert_eq!(report.declared_artifacts[5].label, "tool result");
    assert_eq!(report.declared_artifacts[5].path, "result.json");
    assert_eq!(report.declared_artifacts[5].kind, "json");

    let output = report.to_tool_json();

    assert_eq!(
        output["data"]["declaredArtifacts"][1]["label"],
        json!("runtime trace")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][1]["path"],
        json!("trace.jsonl")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][1]["kind"],
        json!("jsonl")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][3]["label"],
        json!("SARIF report")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][3]["path"],
        json!("report.sarif")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][3]["kind"],
        json!("sarif")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][4]["label"],
        json!("tool input")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][4]["path"],
        json!("input.json")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][4]["kind"],
        json!("json")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][5]["label"],
        json!("tool result")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][5]["path"],
        json!("result.json")
    );
    assert_eq!(
        output["data"]["declaredArtifacts"][5]["kind"],
        json!("json")
    );
}

#[test]
fn report_artifact_manifest_alias_counts_exclude_canonical_fields() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-manifest-canonical-alias-exclusions",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-manifest-canonical-alias-exclusions");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-manifest-canonical-alias-exclusions",
            "artifacts": [
                {"label": "run metadata", "path": "run.json", "kind": "json"},
                {"name": "runtime trace", "file_path": "trace.jsonl", "type": "jsonl"}
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let report = build_run_report(
        temp.path(),
        Some("run-manifest-canonical-alias-exclusions"),
    )
    .unwrap();

    assert!(report.report_markdown.contains(
        "artifacts.json: present - 2 artifact(s), kinds json=1, jsonl=1, canonical 2, aliases labels=1, paths=1, kinds=1, labels run metadata, runtime trace"
    ));
}

#[test]
fn report_fails_on_malformed_artifact_manifest() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-malformed-manifest", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-malformed-manifest");
    fs::write(dir.join("artifacts.json"), "{not-json").unwrap();

    let error = build_run_report(temp.path(), Some("run-malformed-manifest")).unwrap_err();

    assert!(error.to_string().contains("Could not parse"));
    assert!(error.to_string().contains("artifacts.json"));
}

#[test]
fn report_fails_on_non_object_artifact_manifest() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-non-object-manifest",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-non-object-manifest");
    fs::write(dir.join("artifacts.json"), "[]").unwrap();

    let error = build_run_report(temp.path(), Some("run-non-object-manifest")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest is not a JSON object"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_non_array_manifest_artifacts() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-non-array-manifest-artifacts",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-non-array-manifest-artifacts");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-non-array-manifest-artifacts",
            "artifacts": {}
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(temp.path(), Some("run-non-array-manifest-artifacts")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest artifacts is not a JSON array"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_manifest_missing_artifacts() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-missing-manifest-artifacts",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-missing-manifest-artifacts");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-missing-manifest-artifacts"
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(temp.path(), Some("run-missing-manifest-artifacts")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest is missing artifacts array"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_manifest_missing_run_id() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-missing-manifest-run-id",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-missing-manifest-run-id");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "artifacts": []
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(temp.path(), Some("run-missing-manifest-run-id")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest is missing runId"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_manifest_blank_run_id() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-blank-manifest-run-id",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-blank-manifest-run-id");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "runId": "   ",
            "artifacts": []
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(temp.path(), Some("run-blank-manifest-run-id")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest runId is not a non-empty string"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_manifest_blank_snake_case_run_id() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-blank-snake-manifest-run-id",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-blank-snake-manifest-run-id");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "   ",
            "artifacts": []
        }))
        .unwrap(),
    )
    .unwrap();

    let error =
        build_run_report(temp.path(), Some("run-blank-snake-manifest-run-id")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest run_id is not a non-empty string"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_manifest_run_id_mismatch() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-mismatch-manifest-run-id",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-mismatch-manifest-run-id");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "runId": "other-run",
            "artifacts": []
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(temp.path(), Some("run-mismatch-manifest-run-id")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest runId does not match requested run id"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_conflicting_manifest_run_id_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-conflicting-manifest-run-id-aliases",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-conflicting-manifest-run-id-aliases");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "runId": "run-conflicting-manifest-run-id-aliases",
            "run_id": "other-run",
            "artifacts": []
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(
        temp.path(),
        Some("run-conflicting-manifest-run-id-aliases"),
    )
    .unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest runId and run_id disagree"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_conflicting_manifest_artifact_path_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-conflicting-manifest-artifact-path-aliases",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(
        temp.path(),
        "run-conflicting-manifest-artifact-path-aliases",
    );
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-conflicting-manifest-artifact-path-aliases",
            "artifacts": [
                {
                    "label": "run metadata",
                    "path": "run.json",
                    "filePath": "trace.jsonl",
                    "kind": "json"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(
        temp.path(),
        Some("run-conflicting-manifest-artifact-path-aliases"),
    )
    .unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest artifact at index 0 has conflicting path aliases"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_non_string_manifest_artifact_path_alias() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-non-string-manifest-artifact-path-alias",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(
        temp.path(),
        "run-non-string-manifest-artifact-path-alias",
    );
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-non-string-manifest-artifact-path-alias",
            "artifacts": [
                {
                    "label": "run metadata",
                    "filePath": ["run.json"],
                    "kind": "json"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(
        temp.path(),
        Some("run-non-string-manifest-artifact-path-alias"),
    )
    .unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest artifact at index 0 filePath is not a string"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_missing_manifest_artifact_path_alias() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-missing-manifest-artifact-path-alias",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-missing-manifest-artifact-path-alias");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-missing-manifest-artifact-path-alias",
            "artifacts": [
                {
                    "label": "run metadata",
                    "kind": "json"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(
        temp.path(),
        Some("run-missing-manifest-artifact-path-alias"),
    )
    .unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest artifact at index 0 is missing path alias"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_blank_manifest_artifact_path_alias() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-blank-manifest-artifact-path-alias",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-blank-manifest-artifact-path-alias");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-blank-manifest-artifact-path-alias",
            "artifacts": [
                {
                    "label": "run metadata",
                    "path": "   ",
                    "kind": "json"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(
        temp.path(),
        Some("run-blank-manifest-artifact-path-alias"),
    )
    .unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest artifact at index 0 path alias is empty"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_blank_manifest_artifact_kind_alias() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-blank-manifest-artifact-kind-alias",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-blank-manifest-artifact-kind-alias");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-blank-manifest-artifact-kind-alias",
            "artifacts": [
                {
                    "label": "run metadata",
                    "path": "run.json",
                    "kind": "   "
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(
        temp.path(),
        Some("run-blank-manifest-artifact-kind-alias"),
    )
    .unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest artifact at index 0 kind alias is empty"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_manifest_canonical_artifact_kind_mismatch() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-canonical-manifest-artifact-kind-mismatch",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(
        temp.path(),
        "run-canonical-manifest-artifact-kind-mismatch",
    );
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-canonical-manifest-artifact-kind-mismatch",
            "artifacts": [
                {
                    "label": "run metadata",
                    "path": "run.json",
                    "kind": "jsonl"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let error = build_run_report(
        temp.path(),
        Some("run-canonical-manifest-artifact-kind-mismatch"),
    )
    .unwrap_err();
    let message = error.to_string();

    assert!(message.contains(
        "Artifact manifest artifact at index 0 kind does not match canonical artifact contract"
    ));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_non_object_manifest_artifact_entry() {
    let temp = tempdir().unwrap();
    let source = completed_summary(
        temp.path(),
        "run-non-object-manifest-artifact-entry",
        "agentic-sast:scan",
    );
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-non-object-manifest-artifact-entry");
    fs::write(
        dir.join("artifacts.json"),
        serde_json::to_string_pretty(&json!({
            "run_id": "run-non-object-manifest-artifact-entry",
            "artifacts": [
                {
                    "label": "run metadata",
                    "path": "run.json",
                    "kind": "json"
                },
                []
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let error =
        build_run_report(temp.path(), Some("run-non-object-manifest-artifact-entry")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Artifact manifest artifact at index 1 is not a JSON object"));
    assert!(message.contains("artifacts.json"));
}

#[test]
fn report_fails_on_non_file_artifact_manifest() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-non-file-manifest", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-non-file-manifest");
    let manifest_path = dir.join("artifacts.json");
    fs::remove_file(&manifest_path).unwrap();
    fs::create_dir(&manifest_path).unwrap();

    let error = build_run_report(temp.path(), Some("run-non-file-manifest")).unwrap_err();

    assert!(error.to_string().contains("Artifact manifest is not a file"));
    assert!(error.to_string().contains("artifacts.json"));
}

#[test]
fn report_fails_on_non_file_run_metadata() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-non-file-metadata", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let metadata_path = run_dir(temp.path(), "run-non-file-metadata").join("run.json");
    fs::remove_file(&metadata_path).unwrap();
    fs::create_dir(&metadata_path).unwrap();

    let error = build_run_report(temp.path(), Some("run-non-file-metadata")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Run metadata is not a file"));
    assert!(message.contains("run.json"));
}

#[test]
fn report_fails_on_malformed_run_metadata_without_legacy_fallback() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-malformed-metadata", "agentic-sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-malformed-metadata");
    fs::write(dir.join("summary.json"), serde_json::to_string(&source).unwrap()).unwrap();
    fs::write(dir.join("run.json"), "{not-json").unwrap();

    let error = build_run_report(temp.path(), Some("run-malformed-metadata")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Could not parse"));
    assert!(message.contains("run.json"));
    assert!(!message.contains("summary.json"));
}

#[test]
fn report_counts_threat_model_related_cwe_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-cwe-aliases", "threat-model:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-cwe-aliases",
        "threat-model.json",
        "threat model",
        &json!({
            "methodology": "stride",
            "dfd": {"nodes": [], "flows": [], "trustBoundaries": []},
            "relatedCwe": ["CWE-22"],
            "threats": [
                {"id": "T-001", "related_cwe": ["CWE-640"]},
                {"id": "T-002", "cwe": ["CWE-434", "CWE-640"]}
            ],
            "narrative": {
                "input_categories": {
                    "attacker_controlled": ["query params", "uploaded files"],
                    "operatorControlled": ["admin toggles"],
                    "developer_controlled": ["deployment config"],
                    "externalServices": ["Stripe webhook"],
                    "credential_flows": ["POST /auth/login", "POST /credentials/rotate"],
                    "authorizationFlows": ["POST /admin/users"],
                    "file_ingest_flows": ["POST /customers/import-file"],
                    "callbackFlows": ["POST /login/return-to"],
                    "data_egress_flows": ["GET /reports/download"]
                },
                "attackerStories": [{"threatIds": ["T-001"]}, {"threatIds": ["T-002"]}],
                "criticalityBuckets": {"critical": ["auth"], "medium": ["files"]},
                "outOfScope": ["runtime exploit confirmation"],
                "inputCategories": {
                    "sandboxBoundary": ["container boundary"],
                    "assumptions": ["static evidence only"]
                }
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-cwe-aliases")).unwrap();

    assert!(report.report_markdown.contains(
        "threat-model.json: present - methodology stride, 2 threat(s), DFD nodes=0, flows=0, boundaries=0, CWEs CWE-22=1, CWE-434=1, CWE-640=2, attackerControlled=2, operatorControlled=1, developerControlled=1, externalServices=1, credentialFlows=2, authorizationFlows=1, fileIngestFlows=1, dataEgressFlows=1, callbackFlows=1, attackerStories=2, outOfScope=1, sandboxBoundary=1, assumptions=1, criticalityBuckets=2"
    ));
}

#[test]
fn report_summarizes_snake_case_threat_model_trust_boundaries() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-threat-snake", "threat-model:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-threat-snake",
        "threat-model.json",
        "threat model",
        &json!({
            "methodology": "stride",
            "dfd": {
                "nodes": [{"id": "app"}],
                "flows": [{"id": "flow-public"}],
                "trust_boundaries": [{"id": "tb-public"}]
            },
            "threats": []
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-threat-snake")).unwrap();

    assert!(report.report_markdown.contains(
        "threat-model.json: present - methodology stride, 0 threat(s), DFD nodes=1, flows=1, boundaries=1"
    ));
}

#[test]
fn report_summarizes_enveloped_threat_model_document() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-threat-envelope", "threat-model:build");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-threat-envelope",
        "threat-model.json",
        "threat model",
        &json!({
            "status": "completed",
            "data": {
                "document": {
                    "methodology": "pasta",
                    "dfd": {
                        "nodes": [{"id": "api"}],
                        "flows": [{"id": "flow-api"}],
                        "trustBoundaries": [{"id": "tb-api"}]
                    },
                    "threats": [
                        {"id": "T-001", "relatedCwe": ["CWE-20"]}
                    ]
                }
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-threat-envelope")).unwrap();

    assert!(report.report_markdown.contains(
        "threat-model.json: present - methodology pasta, 1 threat(s), DFD nodes=1, flows=1, boundaries=1, CWEs CWE-20=1"
    ));
}

#[test]
fn report_summarizes_canonical_recommendation_distribution() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-recommend", "modules:recommend");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-recommend",
        "recommendations.json",
        "recommendations",
        &json!({
            "summary": "Prioritize scanner and review coverage.",
            "warnings": ["codeql unavailable"],
            "errors": ["semgrep timed out"],
            "availableToolCount": 8,
            "recommendedToolCount": 4,
            "skippedMissingTools": ["deferred:tool"],
            "recommendations": [
                {
                    "tool": "codeql:scan",
                    "priority": "high",
                    "requiresRuntime": false,
                    "reason": "semantic coverage is available",
                    "nextInput": {"suite": "security-extended"}
                },
                {
                    "tool": "threat-model:build",
                    "priority": "medium",
                    "requiresRuntime": false,
                    "reason": "attack-surface signals exist",
                    "nextInput": {"methodology": "stride"},
                    "signals": [
                        "attack-surface risk tiers: critical=1, high=1",
                        "attack-surface kinds: background_job=1, file_upload_parse_path=1, rpc_handler=1",
                        "frameworks: Falcon, Litestar, Sanic"
                    ]
                },
                {"tool": "triage:run", "priority": "high", "requiresRuntime": true},
                {"tool": "verify:finding", "priority": "medium", "requiresRuntime": true}
            ]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-recommend")).unwrap();

    assert!(report.report_markdown.contains(
        "recommendations.json: present - 4 recommendation(s), warnings=1, errors=1, available tools=8, recommended tools=4, skipped missing=1, priority high=2, medium=2, runtime required=2, reasons=2, next inputs=2, attack-surface risk tiers: critical=1, high=1, attack-surface kinds: background_job=1, file_upload_parse_path=1, rpc_handler=1, frameworks: Falcon, Litestar, Sanic, tools codeql:scan, threat-model:build, triage:run"
    ));
}

#[test]
fn report_summarizes_snake_case_recommendation_runtime_flag() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-recommend-snake", "modules:recommend");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-recommend-snake",
        "recommendations.json",
        "recommendations",
        &json!({
            "summary": "Prioritize runtime-backed review.",
            "available_tool_count": 5,
            "recommended_tool_count": 2,
            "skipped_missing_tools": ["deferred:tool"],
            "recommendations": [
                {"tool": "triage:run", "priority": "high", "requires_runtime": true},
                {"module_id": "semgrep", "priority": "medium", "requires_runtime": false}
            ]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-recommend-snake")).unwrap();

    assert!(report.report_markdown.contains(
        "recommendations.json: present - 2 recommendation(s), available tools=5, recommended tools=2, skipped missing=1, priority high=1, medium=1, runtime required=1, tools triage:run, semgrep"
    ));
}

#[test]
fn report_summarizes_recommendation_report_envelope() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-recommend-envelope", "modules:recommend");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-recommend-envelope",
        "recommendations.json",
        "recommendations",
        &json!({
            "status": "completed",
            "data": {
                "recommendation_report": {
                    "summary": "Prioritize scanner and runtime review.",
                    "capabilities": {
                        "available_tool_count": 6,
                        "recommended_tool_count": 2,
                        "skipped_missing_tools": ["deferred:tool"]
                    },
                    "recommendations": [
                        {"tool": "triage:run", "priority": "high", "requires_runtime": true},
                        {"tool": "semgrep:scan", "priority": "medium", "requires_runtime": false}
                    ]
                }
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-recommend-envelope")).unwrap();

    assert!(report.report_markdown.contains(
        "recommendations.json: present - 2 recommendation(s), available tools=6, recommended tools=2, skipped missing=1, priority high=1, medium=1, runtime required=1, tools triage:run, semgrep:scan"
    ));
}

#[test]
fn report_summarizes_data_wrapped_recommendation_report() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-recommend-data", "modules:recommend");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-recommend-data",
        "recommendations.json",
        "recommendations",
        &json!({
            "status": "completed",
            "data": {
                "summary": "Prioritize threat modeling.",
                "warnings": ["codeql unavailable"],
                "errors": ["semgrep timed out"],
                "capabilities": {
                    "availableToolCount": 4,
                    "recommendedToolCount": 1,
                    "skippedMissingTools": ["deferred:tool"]
                },
                "recommendations": [{
                    "tool": "threat-model:build",
                    "priority": "medium",
                    "requiresRuntime": false,
                    "reason": "framework route signals exist",
                    "signals": ["frameworks: Falcon, Litestar, Sanic"],
                    "nextInput": {"target": "/repo"}
                }]
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-recommend-data")).unwrap();

    assert!(report.report_markdown.contains(
        "recommendations.json: present - 1 recommendation(s), warnings=1, errors=1, available tools=4, recommended tools=1, skipped missing=1, priority medium=1, reasons=1, next inputs=1, frameworks: Falcon, Litestar, Sanic, tools threat-model:build"
    ));
}

#[test]
fn report_summarizes_canonical_findings_distribution() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-findings", "sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-findings",
        "findings.json",
        "findings",
        &json!([
            {
                "id": "F-1",
                "severity": "critical",
                "staticProofState": "signal_only",
                "tool": "semgrep:scan",
                "ruleId": "xss",
                "filePath": "app/routes.ts"
            },
            {
                "id": "F-2",
                "severity": "high",
                "static_proof_state": "code_cited",
                "tool": "semgrep:scan",
                "rule_id": "sqli",
                "file_path": "app/db.ts"
            },
            {"id": "F-3", "severity": "high", "proofState": "execution_confirmed", "tool": "codeql:scan", "ruleId": "xss", "filePath": "app/routes.ts"},
            {"id": "F-4", "severity": "medium", "proof_state": "runtime_reviewed"},
            {"id": "F-5", "severity": "medium", "proof_state": "code-cited"},
        ]),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-findings")).unwrap();

    assert!(report.report_markdown.contains(
        "findings.json: present - 5 finding(s), severity critical=1, high=2, medium=2, proof code_cited=2, execution_confirmed=1, runtime_reviewed=1, signal_only=1, root causes 4, tools codeql:scan=1, semgrep:scan=2, rules sqli=1, xss=2, files app/db.ts=1, app/routes.ts=2"
    ));
}

#[test]
fn report_clusters_same_file_same_cwe_findings_into_one_root_cause() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-root-cause", "sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-root-cause",
        "findings.json",
        "findings",
        &json!([
            // Three call sites of one CWE-89 defect in db.ts → one root cause.
            {"id": "F-1", "severity": "high", "cwe": "CWE-89", "filePath": "app/db.ts"},
            {"id": "F-2", "severity": "high", "cwe": "CWE-89", "filePath": "app/db.ts"},
            {"id": "F-3", "severity": "high", "cwe": "CWE-89", "filePath": "app/db.ts"},
            // A distinct defect → its own root cause.
            {"id": "F-4", "severity": "medium", "cwe": "CWE-79", "filePath": "app/view.ts"},
        ]),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-root-cause")).unwrap();

    // 4 findings, but only 2 underlying problems.
    assert!(
        report.report_markdown.contains("4 finding(s)"),
        "report: {}",
        report.report_markdown
    );
    assert!(
        report.report_markdown.contains("root causes 2"),
        "report: {}",
        report.report_markdown
    );
}

#[test]
fn report_omits_root_cause_segment_when_no_findings_cluster() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-no-cluster", "sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-no-cluster",
        "findings.json",
        "findings",
        &json!([
            {"id": "F-1", "severity": "high", "cwe": "CWE-89", "filePath": "app/db.ts"},
            {"id": "F-2", "severity": "high", "cwe": "CWE-79", "filePath": "app/view.ts"},
        ]),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-no-cluster")).unwrap();

    assert!(
        !report.report_markdown.contains("root causes"),
        "no two findings share a root cause: {}",
        report.report_markdown
    );
}

#[test]
fn report_summarizes_findings_with_canonical_severity_buckets() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-findings-severity", "secret-scan:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-findings-severity",
        "findings.json",
        "findings",
        &json!([
            {"id": "F-1", "severity": "ERROR"},
            {"id": "F-2", "severity": "HIGH"},
            {"id": "F-3", "severity": "Warning"},
            {"id": "F-4", "severity": "INFO"},
            {"id": "F-5", "severity": "note"}
        ]),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-findings-severity")).unwrap();

    assert!(report.report_markdown.contains(
        "findings.json: present - 5 finding(s), severity high=2, medium=1, info=2"
    ));
}

#[test]
fn report_summarizes_findings_confidence_distribution() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-findings-confidence", "secret-scan:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-findings-confidence",
        "findings.json",
        "findings",
        &json!([
            {
                "id": "F-1",
                "severity": "high",
                "confidence": "HIGH",
                "cwe": "CWE-89",
                "suppressed": true,
                "references": ["https://example.test/rule"]
            },
            {
                "id": "F-2",
                "severity": "medium",
                "confidence": 0.72,
                "cwe": ["CWE-79", "CWE-89"],
                "snoozed_until": "2027-01-01"
            },
            {
                "id": "F-3",
                "severity": "medium",
                "confidence": 35,
                "remediation": "Rotate the exposed secret."
            },
            {"id": "F-4", "severity": "info", "confidence": "unknown"}
        ]),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-findings-confidence")).unwrap();

    assert!(report.report_markdown.contains(
        "findings.json: present - 4 finding(s), severity high=1, medium=2, info=1, confidence high=1, medium=1, low=1, unknown=1, CWEs CWE-79=1, CWE-89=2, suppressed 1, snoozed 1, remediation 1, references 1"
    ));
}

#[test]
fn report_summarizes_nested_properties_proof_state() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-findings-properties", "codeql:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-findings-properties",
        "findings.json",
        "findings",
        &json!([
            {
                "id": "F-1",
                "severity": "high",
                "properties": {"staticProofState": "source-sink-linked"}
            },
            {
                "id": "F-2",
                "severity": "medium",
                "properties": {"proof_state": "runtime_confirmed"}
            }
        ]),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-findings-properties")).unwrap();

    assert!(report.report_markdown.contains(
        "findings.json: present - 2 finding(s), severity high=1, medium=1, proof runtime_confirmed=1, source_sink_linked=1"
    ));
}

#[test]
fn report_summarizes_enveloped_findings_snapshot() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-findings-envelope", "sast:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-findings-envelope",
        "findings.json",
        "findings",
        &json!({
            "status": "completed",
            "data": {
                "core_findings": [
                    {"id": "F-1", "severity": "HIGH", "confidence": 0.9},
                    {"id": "F-2", "severity": "warning", "proof_state": "source-sink-linked"}
                ]
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-findings-envelope")).unwrap();

    assert!(report.report_markdown.contains(
        "findings.json: present - 2 finding(s), severity high=1, medium=1, proof source_sink_linked=1, confidence high=1"
    ));
}

#[test]
fn report_summarizes_canonical_proof_snapshots() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-proof", "semgrep:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-proof",
        "proof.json",
        "proof",
        &json!({
            "source": "normalized-findings",
            "proofLevel": "runtime-and-static",
            "runtimeVerification": true,
            "countsByState": {"signal_only": 2, "code_cited": 1},
            "findings": [
                {
                    "tool": "semgrep:scan",
                    "ruleId": "js/sql-injection",
                    "filePath": "src/app.ts",
                    "startLine": 12
                },
                {
                    "tool": "codeql:scan",
                    "rule_id": "js/xss",
                    "file_path": "src/view.ts",
                    "start_line": 9
                }
            ]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-proof")).unwrap();

    assert!(
        report.report_markdown.contains(
            "proof.json: present - normalized-findings; proofLevel=runtime-and-static; runtimeVerification=true; findings=2; tools codeql:scan=1, semgrep:scan=1; rules js/sql-injection=1, js/xss=1; files src/app.ts=1, src/view.ts=1; states code_cited=1, signal_only=2"
        ),
        "{}",
        report.report_markdown
    );
}

#[test]
fn report_infers_runtime_proof_summary_from_runtime_state_counts() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-proof-runtime-states", "verify:finding");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-proof-runtime-states",
        "proof.json",
        "proof",
        &json!({
            "source": "normalized-findings",
            "proofLevel": "runtime-and-static",
            "countsByState": {
                "execution_attempted": 1,
                "execution_rejected": 1,
                "runtime_reviewed": 1,
                "signal_only": 0
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-proof-runtime-states")).unwrap();

    assert!(report.report_markdown.contains(
        "proof.json: present - normalized-findings; proofLevel=runtime-and-static; runtimeVerification=true; states execution_attempted=1, execution_rejected=1, runtime_reviewed=1, signal_only=0"
    ));
}

#[test]
fn report_summarizes_snake_case_proof_snapshots() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-proof-snake", "semgrep:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-proof-snake",
        "proof.json",
        "proof",
        &json!({
            "source": "normalized-findings",
            "proof_level": "runtime-and-static",
            "runtime_verification": true,
            "counts_by_state": {"signal_only": 1, "source_sink_linked": 1}
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-proof-snake")).unwrap();

    assert!(report.report_markdown.contains(
        "proof.json: present - normalized-findings; proofLevel=runtime-and-static; runtimeVerification=true; states signal_only=1, source_sink_linked=1"
    ));
}

#[test]
fn report_summarizes_enveloped_proof_snapshot() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-proof-envelope", "semgrep:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-proof-envelope",
        "proof.json",
        "proof",
        &json!({
            "status": "completed",
            "data": {
                "proof": {
                    "source": "normalized-findings",
                    "proofLevel": "static-signal-only",
                    "countsByState": {"signal_only": 1}
                }
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-proof-envelope")).unwrap();

    assert!(report.report_markdown.contains(
        "proof.json: present - normalized-findings; proofLevel=static-signal-only; states signal_only=1"
    ));
}

#[test]
fn report_summarizes_verification_proof_snapshots() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-verify-proof", "verify:finding");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-verify-proof",
        "proof.json",
        "proof",
        &json!({
            "kind": "verification",
            "proofLevel": 4,
            "proofVerdict": "exploited",
            "verified": 1,
            "results": [{"findingId": "F-1", "verdict": "confirmed"}]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-verify-proof")).unwrap();

    assert!(report
        .report_markdown
        .contains("proof.json: present - kind=verification, proofLevel=4, verdict=exploited, verified=1, results=1, result verdicts confirmed=1, result findings=1"));
}

#[test]
fn report_summarizes_enveloped_verification_proof_snapshot() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-verify-proof-envelope", "verify:finding");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-verify-proof-envelope",
        "proof.json",
        "proof",
        &json!({
            "data": {
                "verification": {
                    "kind": "verification",
                    "proof_level": 3,
                    "proof_verdict": "confirmed",
                    "verified_count": 2,
                    "verification_results": [
                        {"finding_id": "F-1", "proof_verdict": "confirmed"},
                        {"finding_id": "F-2", "proof_verdict": "not_reproduced"}
                    ]
                }
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-verify-proof-envelope")).unwrap();

    assert!(report
        .report_markdown
        .contains("proof.json: present - kind=verification, proofLevel=3, verdict=confirmed, verified=2, results=2, result verdicts confirmed=1, not_reproduced=1, result findings=2"));
}

#[test]
fn report_summarizes_snake_case_verification_proof_snapshots() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-verify-proof-snake", "verify:finding");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-verify-proof-snake",
        "proof.json",
        "proof",
        &json!({
            "kind": "verification",
            "proof_level": 2,
            "proof_verdict": "needs-runtime-evidence",
            "verified_count": 1,
            "verification_results": [{"fingerprint": "F-1", "verdict": "needs-runtime-evidence"}]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-verify-proof-snake")).unwrap();

    assert!(report
        .report_markdown
        .contains("proof.json: present - kind=verification, proofLevel=2, verdict=needs-runtime-evidence, verified=1, results=1, result verdicts needs-runtime-evidence=1, result findings=1"));
}

#[test]
fn tool_json_exposes_standard_envelope_and_report_markdown() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-source", "dep-hygiene:check");
    write_run_summary(temp.path(), &source).unwrap();
    fs::remove_file(run_dir(temp.path(), "run-source").join("findings.json")).unwrap();

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
fn report_markdown_surfaces_run_reproducibility_metadata() {
    let temp = tempdir().unwrap();
    let rules = temp.path().join(".kuzushi").join("house-rules");
    fs::create_dir_all(&rules).unwrap();
    fs::write(rules.join("triage.md"), "prefer proof-backed findings").unwrap();
    let prompts = temp.path().join(".kuzushi").join("prompts").join("triage");
    fs::create_dir_all(&prompts).unwrap();
    fs::write(prompts.join("run.md"), "rank exploitable findings first").unwrap();
    let threat_model_path = crate::capabilities::persistent_threat_model_path(temp.path());
    fs::write(threat_model_path, r#"{"methodology":"STRIDE"}"#).unwrap();
    let source = completed_summary(temp.path(), "run-repro", "agentic-sast:scan")
        .with_model(Some("openai:gpt-test".to_string()))
        .with_config_hash(Some("sha256:abc123".to_string()))
        .with_env_fingerprint(vec![RunEnvFingerprint {
            key: "KUZUSHI_DEBUG".to_string(),
            fingerprint: "sha256:debug".to_string(),
        }])
        .with_target_git(Some(RunTargetGitMetadata {
            sha: "abcdef123456".to_string(),
            branch: Some("main".to_string()),
            dirty: true,
        }));
    write_run_summary(temp.path(), &source).unwrap();

    let report = build_run_report(temp.path(), Some("run-repro")).unwrap();

    assert!(report.report_markdown.contains("## Reproducibility"));
    assert!(report.report_markdown.contains(&format!(
        "- Kuzushi Version: {}",
        env!("CARGO_PKG_VERSION")
    )));
    assert!(report.report_markdown.contains("- Platform: "));
    assert!(report
        .report_markdown
        .contains("- Model: openai:gpt-test"));
    assert!(report
        .report_markdown
        .contains("- Config Hash: sha256:abc123"));
    assert!(report.report_markdown.contains("- Git SHA: "));
    assert!(report
        .report_markdown
        .contains("- House Rules: triage sha256:"));
    assert!(report
        .report_markdown
        .contains("- Prompt Overrides: triage:run sha256:"));
    assert!(report
        .report_markdown
        .contains("- Threat Model SHA256: sha256:"));
    assert!(report
        .report_markdown
        .contains("- Environment: KUZUSHI_DEBUG sha256:debug"));
    assert!(report
        .report_markdown
        .contains("- Target Git: abcdef123456 main dirty"));
}

#[test]
fn report_markdown_summarizes_exploit_chain_result_steps() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-chain", "exploit-chain:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-chain",
        "result.json",
        "tool result",
        &json!({
            "status": "completed",
            "summary": "exploit-chain complete",
            "data": {
                "chains": [{
                    "id": "C-0001",
                    "name": "Template render chain",
                    "impactDescription": "Template rendering can execute attacker-controlled input.",
                    "overallSeverity": "ERROR",
                    "steps": [
                        {"filePath": "app.js", "startLine": 3},
                        {"filePath": "app.js", "startLine": 4}
                    ]
                }]
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-chain")).unwrap();

    assert!(report.report_markdown.contains(
        "result.json: present - 1 exploit chain(s), severity high=1, named chains 1, impact descriptions 1, 2 anchored step(s)"
    ));
}

#[test]
fn report_markdown_summarizes_snake_case_exploit_chain_result_steps() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-chain-snake", "exploit-chain:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-chain-snake",
        "result.json",
        "tool result",
        &json!({
            "status": "completed",
            "summary": "exploit-chain complete",
            "data": {
                "exploit_chains": [{
                    "id": "C-0001",
                    "impact_description": "Template rendering can execute attacker-controlled input.",
                    "name": "Template render chain",
                    "overall_severity": "ERROR",
                    "steps": [
                        {"file_path": "app.js", "start_line": 3},
                        {"file_path": "app.js", "start_line": 4}
                    ]
                }]
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-chain-snake")).unwrap();

    assert!(report.report_markdown.contains(
        "result.json: present - 1 exploit chain(s), severity high=1, named chains 1, impact descriptions 1, 2 anchored step(s)"
    ));
}

#[test]
fn report_markdown_summarizes_exploit_chain_step_aliases() {
    let temp = tempdir().unwrap();
    let source = completed_summary(temp.path(), "run-chain-step-aliases", "exploit-chain:scan");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-chain-step-aliases",
        "result.json",
        "tool result",
        &json!({
            "status": "completed",
            "data": {
                "exploitChains": [{
                    "id": "C-0001",
                    "title": "Critical template chain",
                    "impactDescription": "Template rendering can execute attacker-controlled input.",
                    "overallSeverity": "critical",
                    "chainSteps": [{"filePath": "app.js", "startLine": 3}]
                }, {
                    "id": "C-0002",
                    "overallSeverity": "medium",
                    "chain_steps": [{"file_path": "db.js", "start_line": 9}]
                }]
            }
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-chain-step-aliases")).unwrap();

    assert!(report.report_markdown.contains(
        "result.json: present - 2 exploit chain(s), severity critical=1, medium=1, named chains 1, impact descriptions 1, 2 anchored step(s)"
    ));
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
        "tool result",
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
    assert!(
        report
            .report_markdown
            .contains("failures.json: present - status failed, 1 failure(s), stages semgrep:scan")
    );
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

#[test]
fn report_summarizes_snake_case_failure_handoff_stage() {
    let temp = tempdir().unwrap();
    let source = RunSummary::running(
        "run-failed-snake",
        "tool",
        Some("semgrep:scan".to_string()),
        "target",
    )
    .failed("scanner missing");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-failed-snake",
        "failures.json",
        "failure handoff",
        &json!({
            "run_id": "run-failed-snake",
            "status": "failed",
            "failures": [
                {
                    "tool": "semgrep:scan",
                    "status": "failed",
                    "error": "scanner missing",
                    "agent_thread_context": {
                        "failed_stage": "semgrep:scan",
                        "cause": "scanner missing",
                        "what_failed": "semgrep:scan did not complete successfully",
                        "artifacts_available": [
                            {
                                "label": "result",
                                "path": "result.json",
                                "kind": "json"
                            }
                        ],
                        "missing_artifacts": ["proof.json"],
                        "allowed_proof_level": "artifact-review-only",
                        "next_files_or_artifacts_to_inspect": ["result.json"],
                        "recovery_options": ["rerun semgrep"],
                        "fallback_prompt": "Inspect result.json before retrying.",
                        "claims_forbidden": ["exploit proven"]
                    }
                }
            ]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-failed-snake")).unwrap();

    assert!(
        report
            .report_markdown
            .contains("failures.json: present - status failed, 1 failure(s), stages semgrep:scan, proof limits artifact-review-only, available artifacts 1, missing artifacts 1, next artifacts 1, what failed 1, recovery options 1, fallback prompts 1, claims forbidden 1")
    );
    assert_eq!(report.failure_handoffs[0].failed_stage, "semgrep:scan");
    assert_eq!(report.failure_handoffs[0].allowed_proof_level, "artifact-review-only");
}

#[test]
fn report_fails_on_malformed_failure_handoff() {
    let temp = tempdir().unwrap();
    let source = RunSummary::running(
        "run-malformed-failures",
        "tool",
        Some("semgrep:scan".to_string()),
        "target",
    )
    .failed("scanner missing");
    write_run_summary(temp.path(), &source).unwrap();
    let dir = run_dir(temp.path(), "run-malformed-failures");
    fs::write(dir.join("failures.json"), "{not-json").unwrap();

    let error = build_run_report(temp.path(), Some("run-malformed-failures")).unwrap_err();

    assert!(error.to_string().contains("failed to parse"));
    assert!(error.to_string().contains("failures.json"));
}

#[test]
fn report_fails_on_non_file_failure_handoff() {
    let temp = tempdir().unwrap();
    let source = RunSummary::running(
        "run-non-file-failures",
        "tool",
        Some("semgrep:scan".to_string()),
        "target",
    )
    .failed("scanner missing");
    write_run_summary(temp.path(), &source).unwrap();
    let path = run_dir(temp.path(), "run-non-file-failures").join("failures.json");
    fs::remove_file(&path).unwrap();
    fs::create_dir_all(&path).unwrap();

    let error = build_run_report(temp.path(), Some("run-non-file-failures")).unwrap_err();
    let message = error.to_string();

    assert!(message.contains("Run failures artifact is not a file"));
    assert!(message.contains("failures.json"));
}

#[test]
fn report_normalizes_failure_handoff_artifact_aliases() {
    let temp = tempdir().unwrap();
    let source = RunSummary::running(
        "run-failed-artifact-aliases",
        "tool",
        Some("triage:run".to_string()),
        "target",
    )
    .failed("triage failed");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-failed-artifact-aliases",
        "failures.json",
        "failure handoff",
        &json!({
            "run_id": "run-failed-artifact-aliases",
            "status": "failed",
            "failures": [{
                "tool": "triage:run",
                "status": "failed",
                "error": "triage failed",
                "agent_thread_context": {
                    "failed_stage": "triage:run",
                    "cause": "triage failed",
                    "what_failed": "triage did not complete successfully",
                    "artifacts_available": [{
                        "name": "triage transcript",
                        "report_json_path": "triage/transcript.json",
                        "type": "json"
                    }],
                    "missing_artifacts": ["proof.json"],
                    "allowed_proof_level": "artifact-review-only",
                    "next_files_or_artifacts_to_inspect": ["triage/transcript.json"],
                    "recovery_options": ["rerun triage"],
                    "fallback_prompt": "Inspect the triage transcript.",
                    "claims_forbidden": ["verified claim"]
                }
            }]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-failed-artifact-aliases")).unwrap();
    let artifact = &report.failure_handoffs[0].artifacts_available[0];

    assert_eq!(artifact.label, "triage transcript");
    assert_eq!(artifact.path, "triage/transcript.json");
    assert_eq!(artifact.kind, "json");
    assert!(report
        .report_markdown
        .contains("- Available Artifacts: triage/transcript.json"));
}

#[test]
fn report_repairs_failure_handoff_stage_and_cause_from_failure_record() {
    let temp = tempdir().unwrap();
    let source = RunSummary::running(
        "run-failed-legacy",
        "tool",
        Some("semgrep:scan".to_string()),
        "target",
    )
    .failed("scanner missing");
    write_run_summary(temp.path(), &source).unwrap();
    write_run_artifact_json(
        temp.path(),
        "run-failed-legacy",
        "failures.json",
        "failure handoff",
        &json!({
            "runId": "run-failed-legacy",
            "status": "failed",
            "failures": [{
                "tool": "semgrep:scan",
                "status": "failed",
                "error": "scanner missing",
                "agentThreadContext": {
                    "whatFailed": "semgrep:scan did not complete successfully",
                    "artifactsAvailable": [],
                    "missingArtifacts": ["proof.json"],
                    "allowedProofLevel": "artifact-review-only",
                    "nextFilesOrArtifactsToInspect": ["result.json"],
                    "recoveryOptions": ["rerun semgrep"],
                    "fallbackPrompt": "Inspect result.json before retrying.",
                    "claimsForbidden": ["verified claim"]
                }
            }]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-failed-legacy")).unwrap();

    assert!(report.report_markdown.contains("Failed Stage: semgrep:scan"));
    assert!(report.report_markdown.contains("Cause: scanner missing"));
    assert_eq!(report.failure_handoffs[0].failed_stage, "semgrep:scan");
    assert_eq!(report.failure_handoffs[0].cause, "scanner missing");
}

#[test]
fn report_bounds_failure_handoff_lists_for_legacy_artifacts() {
    let temp = tempdir().unwrap();
    let source = RunSummary::running(
        "run-failed-many",
        "tool",
        Some("semgrep:scan".to_string()),
        "target",
    )
    .failed("scanner missing");
    write_run_summary(temp.path(), &source).unwrap();

    let available = numbered_json_artifacts("available", 15);
    write_run_artifact_json(
        temp.path(),
        "run-failed-many",
        "failures.json",
        "failure handoff",
        &json!({
            "runId": "run-failed-many",
            "status": "failed",
            "failures": [{
                "tool": "semgrep:scan",
                "status": "failed",
                "error": "scanner missing",
                "agentThreadContext": {
                    "whatFailed": "semgrep:scan did not complete successfully",
                    "artifactsAvailable": available,
                    "missingArtifacts": numbered_strings("missing", 15),
                    "allowedProofLevel": "artifact-review-only",
                    "nextFilesOrArtifactsToInspect": numbered_strings("next", 15),
                    "recoveryOptions": numbered_strings("recovery", 15),
                    "fallbackPrompt": "Inspect bounded failure artifacts.",
                    "claimsForbidden": numbered_strings("claim", 15)
                }
            }]
        }),
    )
    .unwrap();

    let report = build_run_report(temp.path(), Some("run-failed-many")).unwrap();

    assert!(report.report_markdown.contains("missing-11.json"));
    assert!(!report.report_markdown.contains("missing-12.json"));
    assert!(report.report_markdown.contains("available-11.json"));
    assert!(!report.report_markdown.contains("available-12.json"));
    assert!(report.report_markdown.contains("... and 3 more"));
}

fn numbered_strings(prefix: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{prefix}-{index}.json"))
        .collect()
}

fn numbered_json_artifacts(prefix: &str, count: usize) -> Vec<serde_json::Value> {
    numbered_strings(prefix, count)
        .into_iter()
        .map(|path| json!({ "label": path, "path": path, "kind": "json" }))
        .collect()
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
