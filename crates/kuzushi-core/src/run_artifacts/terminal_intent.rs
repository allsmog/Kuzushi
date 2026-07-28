use super::{checked_run_artifact_path, RunSummary};
use anyhow::{Context, Result};
use std::path::Path;

const TERMINAL_INTENT_LEAF: &str = ".terminal-intent.json";
const TERMINAL_RECEIPT_LEAF: &str = ".typed-terminal";
const MAX_TERMINAL_INTENT_BYTES: usize = 1024 * 1024;

pub(super) fn write_terminal_intent(target: &Path, summary: &RunSummary) -> Result<()> {
    let path = checked_run_artifact_path(target, &summary.run_id, TERMINAL_INTENT_LEAF)?;
    let body = serde_json::to_string(summary)?;
    anyhow::ensure!(
        body.len() <= MAX_TERMINAL_INTENT_BYTES,
        "terminal intent for run {} exceeds the size limit",
        summary.run_id
    );
    crate::fs_atomic::write_atomic(&path, &body)
        .with_context(|| format!("Could not persist terminal intent for run {}", summary.run_id))
}

pub(super) fn load_terminal_intent(target: &Path, run_id: &str) -> Result<Option<RunSummary>> {
    let path = checked_run_artifact_path(target, run_id, TERMINAL_INTENT_LEAF)?;
    let body = match crate::bounded_file::read_utf8_text(&path, MAX_TERMINAL_INTENT_BYTES) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("Could not read {}", path.display())),
    };
    let summary: RunSummary = serde_json::from_str(&body)
        .with_context(|| format!("Terminal intent for run {run_id} is invalid"))?;
    anyhow::ensure!(
        summary.run_id == run_id,
        "terminal intent run id does not match {run_id}"
    );
    anyhow::ensure!(
        summary.status != "running",
        "terminal intent for run {run_id} is not terminal"
    );
    Ok(Some(summary))
}

pub(super) fn clear_terminal_intent_best_effort(target: &Path, run_id: &str) {
    let Ok(path) = checked_run_artifact_path(target, run_id, TERMINAL_INTENT_LEAF) else {
        return;
    };
    if let Err(error) = std::fs::remove_file(&path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            crate::runtime_diagnostics::record_runtime_diagnostic(
                "run-terminal",
                format!("could not remove stale terminal intent {}: {error}", path.display()),
            );
        }
    }
}

pub(super) fn mark_typed_terminal(target: &Path, run_id: &str) -> Result<()> {
    let path = checked_run_artifact_path(target, run_id, TERMINAL_RECEIPT_LEAF)?;
    crate::fs_atomic::write_atomic(&path, "typed terminal persisted\n")
        .with_context(|| format!("Could not mark the typed terminal for run {run_id}"))
}

pub(super) fn has_typed_terminal_marker(target: &Path, run_id: &str) -> bool {
    checked_run_artifact_path(target, run_id, TERMINAL_RECEIPT_LEAF)
        .ok()
        .and_then(|path| std::fs::symlink_metadata(path).ok())
        .is_some_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

pub(super) fn has_terminal_intent(target: &Path, run_id: &str) -> bool {
    checked_run_artifact_path(target, run_id, TERMINAL_INTENT_LEAF)
        .ok()
        .and_then(|path| std::fs::symlink_metadata(path).ok())
        .is_some_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}
