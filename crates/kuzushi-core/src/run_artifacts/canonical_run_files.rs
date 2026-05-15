use super::canonical_recommendations::recommendations_snapshot_value;
use super::canonical_proof::proof_snapshot_value;
use super::run_dir;
use super::write_run_artifact_json;
use super::write_run_artifact_text;
use super::RunArtifact;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const JSON_SNAPSHOT_FILES: &[(&str, &str)] = &[
    ("context.json", "No context snapshot was recorded for this run."),
    (
        "attack-surface.json",
        "No attack-surface snapshot was recorded for this run.",
    ),
    (
        "threat-model.json",
        "No threat-model snapshot was recorded for this run.",
    ),
    (
        "recommendations.json",
        "No module recommendations were recorded for this run.",
    ),
    ("findings.json", "No findings snapshot was recorded for this run."),
    ("proof.json", "No proof snapshot was recorded for this run."),
];

pub(crate) fn ensure_canonical_run_files(
    target: &Path,
    run_id: &str,
    status: &str,
) -> Result<()> {
    let dir = run_dir(target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    for (file_name, summary) in JSON_SNAPSHOT_FILES {
        write_json_if_missing(dir.join(file_name), missing_snapshot(run_id, status, summary))?;
    }
    write_empty_failures_marker(dir.join("failures.json"), run_id, status)?;
    write_json_if_missing(dir.join("artifacts.json"), empty_manifest(run_id))?;
    write_text_if_missing(dir.join("events.jsonl"), "")?;
    write_text_if_missing(dir.join("trace.jsonl"), "")?;
    write_text_if_missing(dir.join("report.md"), missing_report(run_id, status))?;
    Ok(())
}

pub(crate) fn record_canonical_snapshot_artifacts(
    target: &Path,
    run_id: &str,
    output: &Value,
) -> Vec<RunArtifact> {
    let mut artifacts = Vec::new();
    record_json_snapshot(&mut artifacts, target, run_id, output, context_snapshot());
    record_json_snapshot(&mut artifacts, target, run_id, output, attack_surface_snapshot());
    record_json_snapshot(&mut artifacts, target, run_id, output, threat_model_snapshot());
    record_recommendations_snapshot(&mut artifacts, target, run_id, output);
    record_json_snapshot(&mut artifacts, target, run_id, output, findings_snapshot());
    record_proof_snapshot(&mut artifacts, target, run_id, output);
    record_report_artifacts(&mut artifacts, target, run_id, output);
    artifacts
}

fn record_report_artifacts(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    output: &Value,
) {
    record_markdown_report_artifact(artifacts, target, run_id, output);
    record_sarif_report_artifact(artifacts, target, run_id, output);
}

fn record_markdown_report_artifact(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    output: &Value,
) {
    if let Some(markdown) = string_at(output, &["/data/reportMarkdown", "/reportMarkdown"]) {
        push_text_artifact(artifacts, target, run_id, "report.md", "report", "markdown", markdown);
    }
}

fn record_sarif_report_artifact(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    output: &Value,
) {
    if let Some(sarif) = sarif_at(output, &["/data/reportSarif", "/reportSarif"]) {
        push_text_artifact(artifacts, target, run_id, "report.sarif", "sarif", "sarif", &sarif);
    }
}

fn push_text_artifact(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    leaf: &str,
    label: &str,
    kind: &str,
    body: &str,
) {
    if let Ok(artifact) = write_text_artifact(target, run_id, leaf, label, kind, body) {
        artifacts.push(artifact);
    }
}

struct JsonSnapshotSpec<'a> {
    leaf: &'a str,
    label: &'a str,
    pointers: &'a [&'a str],
}

fn context_snapshot() -> JsonSnapshotSpec<'static> {
    JsonSnapshotSpec {
        leaf: "context.json",
        label: "context snapshot",
        pointers: &["/data/snapshot", "/data/context", "/context", "/contextSnapshot"],
    }
}

fn attack_surface_snapshot() -> JsonSnapshotSpec<'static> {
    JsonSnapshotSpec {
        leaf: "attack-surface.json",
        label: "attack surface",
        pointers: &[
            "/data/snapshot/attackSurfaceMap",
            "/data/attackSurfaceMap",
            "/data/attackSurface",
            "/attackSurfaceMap",
            "/attackSurface",
        ],
    }
}

fn threat_model_snapshot() -> JsonSnapshotSpec<'static> {
    JsonSnapshotSpec {
        leaf: "threat-model.json",
        label: "threat model",
        pointers: &["/data/document", "/data/threatModel", "/document", "/threatModel"],
    }
}

fn findings_snapshot() -> JsonSnapshotSpec<'static> {
    JsonSnapshotSpec {
        leaf: "findings.json",
        label: "findings",
        pointers: &["/data/coreFindings", "/data/findings", "/findings"],
    }
}

fn missing_snapshot(run_id: &str, status: &str, summary: &str) -> Value {
    json!({
        "runId": run_id,
        "status": "skipped",
        "runStatus": status,
        "summary": summary,
        "artifacts": [],
        "warnings": [summary],
        "errors": []
    })
}

fn record_json_snapshot(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    output: &Value,
    spec: JsonSnapshotSpec<'_>,
) {
    let Some(value) = value_at(output, spec.pointers) else {
        return;
    };
    if let Ok(artifact) = write_run_artifact_json(target, run_id, spec.leaf, spec.label, value) {
        artifacts.push(artifact);
    }
}

fn record_recommendations_snapshot(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    output: &Value,
) {
    let Some(value) = recommendations_snapshot_value(output) else {
        return;
    };
    if let Ok(artifact) =
        write_run_artifact_json(target, run_id, "recommendations.json", "recommendations", value)
    {
        artifacts.push(artifact);
    }
}

fn record_proof_snapshot(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    output: &Value,
) {
    let Some(value) = proof_snapshot_value(output) else {
        return;
    };
    if let Ok(artifact) = write_run_artifact_json(target, run_id, "proof.json", "proof", &value) {
        artifacts.push(artifact);
    }
}

fn value_at<'a>(output: &'a Value, pointers: &[&str]) -> Option<&'a Value> {
    pointers
        .iter()
        .filter_map(|pointer| output.pointer(pointer))
        .find(|value| !value.is_null())
}

fn string_at<'a>(output: &'a Value, pointers: &[&str]) -> Option<&'a str> {
    value_at(output, pointers).and_then(Value::as_str)
}

fn sarif_at(output: &Value, pointers: &[&str]) -> Option<String> {
    let value = value_at(output, pointers)?;
    value
        .as_str()
        .map(str::to_string)
        .or_else(|| serde_json::to_string_pretty(value).ok())
}

fn write_text_artifact(
    target: &Path,
    run_id: &str,
    leaf: &str,
    label: &str,
    kind: &str,
    body: &str,
) -> Result<RunArtifact> {
    write_run_artifact_text(target, run_id, leaf, label, kind, body)
}

fn empty_failures(run_id: &str, status: &str) -> Value {
    json!({
        "runId": run_id,
        "status": status,
        "failures": []
    })
}

fn empty_manifest(run_id: &str) -> Value {
    json!({
        "runId": run_id,
        "artifacts": []
    })
}

fn missing_report(run_id: &str, status: &str) -> String {
    format!("# Kuzushi Run {run_id}\n\nStatus: {status}\n\nNo report was recorded for this run.\n")
}

fn write_json_if_missing(path: PathBuf, value: Value) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    write_json(path, value)
}

fn write_empty_failures_marker(path: PathBuf, run_id: &str, status: &str) -> Result<()> {
    if failure_file_has_failures(&path) {
        return Ok(());
    }
    write_json(path, empty_failures(run_id, status))
}

fn failure_file_has_failures(path: &Path) -> bool {
    let Ok(body) = fs::read_to_string(path) else {
        return false;
    };
    serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|value| value.get("failures").and_then(Value::as_array).cloned())
        .is_some_and(|failures| !failures.is_empty())
}

fn write_json(path: PathBuf, value: Value) -> Result<()> {
    let body = format!("{}\n", serde_json::to_string_pretty(&value)?);
    fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))
}

fn write_text_if_missing(path: PathBuf, body: impl AsRef<str>) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    fs::write(&path, body.as_ref()).with_context(|| format!("Could not write {}", path.display()))
}
