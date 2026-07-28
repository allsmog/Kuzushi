use super::{load_run_summary, read_run_artifact_bytes};
use crate::run_lifecycle::RunItemStatus;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, PartialEq)]
pub struct PersistedRunTerminalOutcome {
    pub status: RunItemStatus,
    pub result: Value,
}

pub fn load_persisted_run_terminal_outcome(
    target: impl AsRef<Path>,
    run_id: &str,
) -> Result<PersistedRunTerminalOutcome> {
    let target = target.as_ref();
    let summary = load_run_summary(target, run_id)?;
    let status = RunItemStatus::from_label(&summary.status)
        .with_context(|| format!("run {run_id} has unknown status {:?}", summary.status))?;
    anyhow::ensure!(status.is_terminal(), "run {run_id} is not terminal");
    let (_, bytes) = read_run_artifact_bytes(target, run_id, "result.json")
        .require("Persisted tool result")?;
    let result: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("Persisted tool result for run {run_id} is malformed"))?;
    anyhow::ensure!(
        result.get("status").and_then(Value::as_str) == Some(status.label()),
        "persisted result status disagrees with run summary for run {run_id}"
    );
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?;
    let terminal = projection
        .terminal
        .context("persisted run has no typed terminal outcome")?;
    anyhow::ensure!(
        terminal.status == status,
        "typed terminal status disagrees with run summary for run {run_id}"
    );
    Ok(PersistedRunTerminalOutcome { status, result })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_artifacts::{
        try_record_tool_run_canceled_observed, try_record_tool_run_complete_observed,
        try_record_tool_run_started_with_reproducibility, ToolRunRecord,
    };

    #[test]
    fn loads_only_an_agreeing_host_persisted_terminal_outcome() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "persisted-terminal-outcome";
        let record = ToolRunRecord::new(target.path(), run_id, "run", "test:tool");
        try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        try_record_tool_run_complete_observed(
            record,
            &serde_json::json!({"ok": true, "status": "completed", "data": {}}),
            None,
        )
        .unwrap();

        let outcome = load_persisted_run_terminal_outcome(target.path(), run_id).unwrap();

        assert_eq!(outcome.status, RunItemStatus::Completed);
        assert_eq!(outcome.result["status"], "completed");
    }

    #[test]
    fn preserves_host_owned_canceled_status() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "persisted-canceled-outcome";
        let record = ToolRunRecord::new(target.path(), run_id, "run", "test:tool");
        try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        try_record_tool_run_canceled_observed(record, "operator canceled", None).unwrap();

        let outcome = load_persisted_run_terminal_outcome(target.path(), run_id).unwrap();

        assert_eq!(outcome.status, RunItemStatus::Canceled);
        assert_eq!(outcome.result["status"], "canceled");
    }
}
