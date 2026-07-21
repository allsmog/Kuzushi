//! Headless batch contract for `kuzushi run`: deterministic exit codes and
//! the terminal `done.json` sentinel.
//!
//! Findings and run results stay in their canonical stores (`findings.db`,
//! `run.json`, `result.json`); this module only gives an unattended poller
//! two cheap signals:
//!
//! - **Exit code.** `0` = tool completed or was explicitly skipped;
//!   `2` = the run could not be prepared (unknown tool, bad input, missing
//!   workspace — retrying the same job is pointless); `3` = the tool executed
//!   and failed; `4` = the tool returned `status=partial`. `1` remains the
//!   generic anyhow path for unexpected operational errors.
//! - **`done.json` sentinel.** Written atomically into the run directory
//!   after terminal persistence, for every prepared run. Its presence means
//!   the run reached a terminal envelope; a run directory whose `run.json`
//!   still says `running`, with no sentinel and a dead `processId`, crashed.

use anyhow::{Context, Result};
use kuzushi_core::{tool_result_status, ToolResultStatus};
use serde_json::json;
use std::path::{Path, PathBuf};

pub(crate) const EXIT_RUN_PREPARE_FAILED: i32 = 2;
pub(crate) const EXIT_RUN_TOOL_FAILED: i32 = 3;
pub(crate) const EXIT_RUN_TOOL_PARTIAL: i32 = 4;

/// Typed failure carrying the batch exit code. `run_tool_command` returns it
/// as an ordinary `anyhow` error so in-process callers (tests, dispatch) see
/// a normal `Err`; only the top-level CLI entry maps it to `process::exit`.
#[derive(Debug)]
pub(crate) struct RunCommandExit {
    code: i32,
    message: String,
}

impl RunCommandExit {
    pub(crate) fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn code(&self) -> i32 {
        self.code
    }
}

impl std::fmt::Display for RunCommandExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RunCommandExit {}

pub(crate) fn run_exit_code(output: &serde_json::Value) -> i32 {
    match tool_result_status(output) {
        ToolResultStatus::Completed | ToolResultStatus::Skipped => 0,
        ToolResultStatus::Partial => EXIT_RUN_TOOL_PARTIAL,
        ToolResultStatus::Failed => EXIT_RUN_TOOL_FAILED,
    }
}

fn run_status_label(output: &serde_json::Value) -> &'static str {
    match tool_result_status(output) {
        ToolResultStatus::Completed => "completed",
        ToolResultStatus::Partial => "partial",
        ToolResultStatus::Skipped => "skipped",
        ToolResultStatus::Failed => "failed",
    }
}

/// Atomically publish the terminal sentinel next to `run.json`. Best-effort
/// at the call site: a sentinel failure must never change the run outcome.
pub(crate) fn write_done_sentinel(
    target: &Path,
    run_id: &str,
    tool: &str,
    output: &serde_json::Value,
    exit_code: i32,
) -> Result<PathBuf> {
    let directory = kuzushi_core::run_dir(target, run_id);
    anyhow::ensure!(
        directory.is_dir(),
        "run directory {} does not exist",
        directory.display()
    );
    let body = format!(
        "{}\n",
        serde_json::to_string_pretty(&json!({
            "runId": run_id,
            "tool": tool,
            "status": run_status_label(output),
            "ok": exit_code == 0,
            "exitCode": exit_code,
        }))?
    );
    let staged = directory.join(".done.json.tmp");
    let published = directory.join("done.json");
    std::fs::write(&staged, body)
        .with_context(|| format!("could not stage {}", staged.display()))?;
    std::fs::rename(&staged, &published)
        .with_context(|| format!("could not publish {}", published.display()))?;
    Ok(published)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exit_codes_are_deterministic_per_tool_result_status() {
        assert_eq!(run_exit_code(&json!({"status": "completed"})), 0);
        assert_eq!(run_exit_code(&json!({"status": "skipped"})), 0);
        assert_eq!(
            run_exit_code(&json!({"status": "partial"})),
            EXIT_RUN_TOOL_PARTIAL
        );
        assert_eq!(
            run_exit_code(&json!({"status": "failed"})),
            EXIT_RUN_TOOL_FAILED
        );
        assert_eq!(run_exit_code(&json!({"ok": false})), EXIT_RUN_TOOL_FAILED);
    }

    #[test]
    fn typed_exit_survives_the_anyhow_boundary() {
        let error = anyhow::Error::new(RunCommandExit::new(
            EXIT_RUN_PREPARE_FAILED,
            "unknown tool nope:nope",
        ));
        let exit = error
            .downcast_ref::<RunCommandExit>()
            .expect("exit must be recoverable from anyhow");
        assert_eq!(exit.code(), EXIT_RUN_PREPARE_FAILED);
        assert_eq!(error.to_string(), "unknown tool nope:nope");
    }

    #[test]
    fn sentinel_is_published_atomically_into_the_run_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "run-000-test";
        std::fs::create_dir_all(kuzushi_core::run_dir(tmp.path(), run_id)).unwrap();
        let output = json!({"status": "completed", "ok": true});

        let path = write_done_sentinel(tmp.path(), run_id, "workspace:status", &output, 0)
            .expect("sentinel write");

        let body: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(body["runId"], run_id);
        assert_eq!(body["tool"], "workspace:status");
        assert_eq!(body["status"], "completed");
        assert_eq!(body["ok"], true);
        assert_eq!(body["exitCode"], 0);
        assert!(!path.with_file_name(".done.json.tmp").exists());
    }

    #[test]
    fn sentinel_refuses_a_missing_run_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let output = json!({"status": "completed"});
        assert!(write_done_sentinel(tmp.path(), "run-missing", "t:t", &output, 0).is_err());
    }
}
