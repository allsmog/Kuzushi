use super::artifact_manifest::record_canonical_run_artifacts;
use super::canonical_run_markers::{write_empty_failures_marker, write_missing_report_marker};
use super::ensure_run_dir;
use super::write_run_artifact_text;
use super::RunArtifact;
use crate::artifact_contract::{canonical_run_artifact_spec, optional_run_artifact_spec, CanonicalRunArtifactSpec};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn ensure_canonical_run_files(target: &Path, run_id: &str, status: &str) -> Result<()> {
    restore_canonical_run_file_placeholders(target, run_id, status)?;
    record_canonical_run_artifacts(target, run_id)?;
    Ok(())
}

pub(crate) fn restore_canonical_run_file_placeholders(
    target: &Path,
    run_id: &str,
    status: &str,
) -> Result<()> {
    let dir = ensure_run_dir(target, run_id)?;
    write_empty_failures_marker(
        target,
        run_id,
        required_artifact_spec("failures.json").leaf,
        status,
    )?;
    write_json_if_missing(
        dir.join(required_artifact_spec("artifacts.json").leaf),
        empty_manifest(run_id),
    )?;
    write_text_if_missing(dir.join(required_artifact_spec("events.jsonl").leaf), "")?;
    write_text_if_missing(dir.join(required_artifact_spec("items.jsonl").leaf), "")?;
    write_missing_report_marker(
        target,
        run_id,
        required_artifact_spec("report.md").leaf,
        status,
    )?;
    Ok(())
}

pub(crate) fn record_report_artifacts(
    target: &Path,
    run_id: &str,
    output: &Value,
) -> Result<Vec<RunArtifact>> {
    let mut artifacts = Vec::new();
    record_markdown_report_artifact(&mut artifacts, target, run_id, output)?;
    record_sarif_report_artifact(&mut artifacts, target, run_id, output)?;
    Ok(artifacts)
}

fn record_markdown_report_artifact(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    output: &Value,
) -> Result<()> {
    if let Some(markdown) = string_at(output, &["/data/reportMarkdown", "/reportMarkdown"]) {
        push_text_artifact(artifacts, target, run_id, report_artifact_spec(), markdown)?;
    }
    Ok(())
}

fn record_sarif_report_artifact(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    output: &Value,
) -> Result<()> {
    if let Some(sarif) = sarif_at(output, &["/data/reportSarif", "/reportSarif"]) {
        push_text_artifact(artifacts, target, run_id, sarif_artifact_spec(), &sarif)?;
    }
    Ok(())
}

fn push_text_artifact(
    artifacts: &mut Vec<RunArtifact>,
    target: &Path,
    run_id: &str,
    spec: &CanonicalRunArtifactSpec,
    body: &str,
) -> Result<()> {
    artifacts.push(write_text_artifact(target, run_id, spec, body)?);
    Ok(())
}

fn required_artifact_spec(leaf: &str) -> &'static CanonicalRunArtifactSpec {
    canonical_run_artifact_spec(leaf).expect("canonical snapshot artifact must be in shared spec")
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
