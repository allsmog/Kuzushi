use anyhow::Result;
use kuzushi_core::run_artifacts::{
    try_record_tool_run_complete, try_record_tool_run_failed, ToolRunRecord,
};
use std::path::Path;

pub(crate) fn finish_cli_tool_run(
    target: &Path,
    run_id: &str,
    tool: &str,
    output: &serde_json::Value,
) -> Result<()> {
    try_record_tool_run_complete(ToolRunRecord::new(target, run_id, "run", tool), output)
}

#[cfg(test)]
pub(crate) fn fail_cli_tool_run(target: &Path, run_id: &str, tool: &str, error: &str) {
    kuzushi_core::run_artifacts::record_tool_run_failed(
        ToolRunRecord::new(target, run_id, "run", tool),
        error,
    );
}

pub(crate) fn try_fail_cli_tool_run(
    target: &Path,
    run_id: &str,
    tool: &str,
    error: &str,
) -> Result<()> {
    try_record_tool_run_failed(ToolRunRecord::new(target, run_id, "run", tool), error)
}
