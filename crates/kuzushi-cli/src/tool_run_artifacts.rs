use kuzushi_core::run_artifacts::{
    record_tool_run_complete, record_tool_run_failed, ToolRunRecord,
};
use std::path::Path;

pub(crate) fn finish_cli_tool_run(
    target: &Path,
    run_id: &str,
    tool: &str,
    output: &serde_json::Value,
) {
    record_tool_run_complete(ToolRunRecord::new(target, run_id, "run", tool), output);
}

pub(crate) fn fail_cli_tool_run(target: &Path, run_id: &str, tool: &str, error: &str) {
    record_tool_run_failed(ToolRunRecord::new(target, run_id, "run", tool), error);
}
