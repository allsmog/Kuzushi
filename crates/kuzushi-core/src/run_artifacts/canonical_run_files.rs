use super::artifact_manifest::record_canonical_run_artifacts;
use super::canonical_proof::proof_snapshot_value;
use super::canonical_run_markers::{
    write_empty_failures_marker, write_missing_report_marker,
};
use super::canonical_recommendations::recommendations_snapshot_value;
use super::run_dir;
use super::write_run_artifact_json;
use super::write_run_artifact_text;
use super::RunArtifact;
use crate::artifact_contract::{
    canonical_run_artifact_spec, derived_run_artifact_spec, optional_run_artifact_spec,
    CanonicalRunArtifactSpec,
};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn ensure_canonical_run_files(
    target: &Path,
    run_id: &str,
    status: &str,
) -> Result<()> {
    let dir = run_dir(target, run_id);
    fs::create_dir_all(&dir).with_context(|| format!("Could not create {}", dir.display()))?;
    write_empty_failures_marker(dir.join(required_artifact_spec("failures.json").leaf), run_id, status)?;
    write_json_if_missing(
        dir.join(required_artifact_spec("artifacts.json").leaf),
        empty_manifest(run_id),
    )?;
    write_text_if_missing(dir.join(required_artifact_spec("events.jsonl").leaf), "")?;
    write_text_if_missing(dir.join(required_artifact_spec("trace.jsonl").leaf), "")?;
    write_missing_report_marker(
        dir.join(required_artifact_spec("report.md").leaf),
        run_id,
        status,
    )?;
    record_canonical_run_artifacts(target, run_id)?;
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
        push_text_artifact(artifacts, target, run_id, report_artifact_spec(), markdown);
    }
}

fn record_sarif_report_artifact(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    output: &Value,
) {
    if let Some(sarif) = sarif_at(output, &["/data/reportSarif", "/reportSarif"]) {
        push_text_artifact(artifacts, target, run_id, sarif_artifact_spec(), &sarif);
    }
}

fn push_text_artifact(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    spec: &CanonicalRunArtifactSpec,
    body: &str,
) {
    if let Ok(artifact) = write_text_artifact(target, run_id, spec, body) {
        artifacts.push(artifact);
    }
}

struct JsonSnapshotSpec<'a> {
    leaf: &'a str,
    pointers: &'a [&'a str],
}

fn context_snapshot() -> JsonSnapshotSpec<'static> {
    JsonSnapshotSpec {
        leaf: "context.json",
        pointers: &["/data/snapshot", "/data/context", "/context", "/contextSnapshot"],
    }
}

fn attack_surface_snapshot() -> JsonSnapshotSpec<'static> {
    JsonSnapshotSpec {
        leaf: "attack-surface.json",
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
        pointers: &["/data/document", "/data/threatModel", "/document", "/threatModel"],
    }
}

fn findings_snapshot() -> JsonSnapshotSpec<'static> {
    JsonSnapshotSpec {
        leaf: "findings.json",
        pointers: &["/data/coreFindings", "/data/findings", "/coreFindings", "/findings"],
    }
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
    let artifact_spec = derived_artifact_spec(spec.leaf);
    if let Ok(artifact) =
        write_run_artifact_json(target, run_id, artifact_spec.leaf, artifact_spec.label, value)
    {
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
    let spec = derived_artifact_spec("recommendations.json");
    if let Ok(artifact) = write_run_artifact_json(target, run_id, spec.leaf, spec.label, value) {
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
    let spec = derived_artifact_spec("proof.json");
    if let Ok(artifact) = write_run_artifact_json(target, run_id, spec.leaf, spec.label, &value) {
        artifacts.push(artifact);
    }
}

fn required_artifact_spec(leaf: &str) -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec(leaf).expect("canonical snapshot artifact must be in shared spec")
}

fn derived_artifact_spec(leaf: &str) -> &'static CanonicalRunArtifactSpec {
    derived_run_artifact_spec(leaf).expect("derived snapshot artifact must be in shared spec")
}

fn report_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    required_artifact_spec("report.md")
}

fn sarif_artifact_spec() -> &'static CanonicalRunArtifactSpec {
    optional_run_artifact_spec("report.sarif")
        .expect("SARIF report artifact must be in shared optional spec")
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
    spec: &CanonicalRunArtifactSpec,
    body: &str,
) -> Result<RunArtifact> {
    write_run_artifact_text(target, run_id, spec.leaf, spec.label, spec.kind, body)
}

fn empty_manifest(run_id: &str) -> Value {
    json!({
        "runId": run_id,
        "artifacts": []
    })
}

fn write_json_if_missing(path: PathBuf, value: Value) -> Result<()> {
    if missing_file_target_exists(&path, "Canonical JSON artifact target")? {
        return Ok(());
    }
    write_json(path, value)
}

fn write_json(path: PathBuf, value: Value) -> Result<()> {
    let body = format!("{}\n", serde_json::to_string_pretty(&value)?);
    crate::fs_atomic::write_atomic(&path, &body)
        .with_context(|| format!("Could not write {}", path.display()))
}

fn write_text_if_missing(path: PathBuf, body: impl AsRef<str>) -> Result<()> {
    if missing_file_target_exists(&path, "Canonical text artifact target")? {
        return Ok(());
    }
    crate::fs_atomic::write_atomic(&path, body.as_ref())
        .with_context(|| format!("Could not write {}", path.display()))
}

fn missing_file_target_exists(path: &Path, label: &str) -> Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => anyhow::bail!("{label} is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}
