//! Durable tool-supplied input, written before a runtime request can start.
use super::*;
use serde_json::json;

const LEAF: &str = "prepared-model-input.json";
const MAX_BYTES: usize = 1024 * 1024;

pub(crate) fn retain_prepared_model_input(
    target: &Path,
    run_id: &str,
    tool: &str,
    data: &Value,
) -> Result<RunArtifact> {
    validate_document(&data["inputDocument"])?;
    let _guard = super::run_ledger::acquire_run_terminal_lock(target, run_id)?;
    anyhow::ensure!(
        !is_recorded(target, run_id)?,
        "Prepared input already retained; use a new run for another request"
    );
    require_absent(target, run_id)?;
    let value = json!({"schemaVersion":1,"runId":run_id,"tool":tool,"data":data});
    write_run_artifact_json_bounded(
        target,
        run_id,
        LEAF,
        "Prepared model input",
        &value,
        MAX_BYTES,
    )
    .context("Could not retain prepared model input; no runtime request started")
}

pub(super) fn attach(target: &Path, run_id: &str, mut output: Value) -> Value {
    if !output["data"]["inputDocument"].is_null() {
        return output;
    }
    let document = match load(target, run_id) {
        Ok(None) => return output,
        Ok(Some(document)) => document,
        Err(error) => {
            json!({"schemaVersion":1,"error":format!("Prepared input unavailable: {error:#}")})
        }
    };
    if !output["data"].is_object() {
        output["data"] = json!({});
    }
    output["data"]["inputDocument"] = document;
    output
}

fn load(target: &Path, run_id: &str) -> Result<Option<Value>> {
    let path = checked_run_artifact_path(target, run_id, LEAF)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return missing_input(target, run_id)
        }
        other => {
            other?;
        }
    }
    let (_, text) = read_run_artifact_text_bounded(target, run_id, LEAF, MAX_BYTES as u64)?;
    authenticate(target, run_id, &text)?;
    let value: Value = serde_json::from_str(&text)?;
    validate_identity(&value, run_id)?;
    validate_document(&value["data"]["inputDocument"])?;
    Ok(Some(value["data"]["inputDocument"].clone()))
}

fn is_recorded(target: &Path, run_id: &str) -> Result<bool> {
    Ok(load_run_artifacts(target, run_id)?
        .iter()
        .any(|artifact| artifact.path == LEAF))
}

fn missing_input(target: &Path, run_id: &str) -> Result<Option<Value>> {
    anyhow::ensure!(
        !is_recorded(target, run_id)?,
        "Prepared input file is missing after retention"
    );
    Ok(None)
}

fn require_absent(target: &Path, run_id: &str) -> Result<()> {
    let path = checked_run_artifact_path(target, run_id, LEAF)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => anyhow::bail!("Prepared input already exists; use a new run for another request"),
    }
}

fn validate_identity(value: &Value, run_id: &str) -> Result<()> {
    anyhow::ensure!(
        value["schemaVersion"] == 1 && value["runId"] == run_id,
        "Prepared input identity does not match this run"
    );
    Ok(())
}

fn authenticate(target: &Path, run_id: &str, text: &str) -> Result<()> {
    let reference = load_run_artifact_object_reference(target, run_id, LEAF)?;
    anyhow::ensure!(
        reference.size_bytes == text.len() as u64
            && reference.hash == crate::content_store::object_hash(reference.kind, text.as_bytes()),
        "Prepared input changed since retention"
    );
    Ok(())
}

fn validate_document(document: &Value) -> Result<()> {
    anyhow::ensure!(
        document["schemaVersion"] == 1 && document["text"].is_string(),
        "Prepared input requires a version 1 text document"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
