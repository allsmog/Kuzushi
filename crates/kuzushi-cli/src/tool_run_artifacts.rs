use anyhow::Result;
#[cfg(test)]
use kuzushi_core::run_artifacts::try_record_tool_run_complete;
use kuzushi_core::run_artifacts::{
    try_record_tool_run_complete_observed, try_record_tool_run_complete_settled,
    try_record_tool_run_failed_observed_with_execution, try_record_tool_run_failed_settled,
    ToolRunRecord,
};
use std::path::Path;

#[cfg(test)]
pub(crate) fn finish_cli_tool_run(
    target: &Path,
    run_id: &str,
    tool: &str,
    output: &serde_json::Value,
) -> Result<()> {
    try_record_tool_run_complete(ToolRunRecord::new(target, run_id, "run", tool), output)
}

pub(crate) fn finish_cli_tool_run_settled(
    target: &Path,
    run_id: &str,
    tool: &str,
    output: &serde_json::Value,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    completion: kuzushi_core::PendingToolCallCompletion,
) -> Result<()> {
    try_record_tool_run_complete_settled(
        ToolRunRecord::new(target, run_id, "run", tool),
        output,
        observation,
        completion,
    )
}

pub(crate) fn finish_cli_tool_run_observed(
    target: &Path,
    run_id: &str,
    tool: &str,
    output: &serde_json::Value,
    observation: Option<&kuzushi_core::run_lifecycle::RunObservationHandle>,
) -> Result<()> {
    try_record_tool_run_complete_observed(
        ToolRunRecord::new(target, run_id, "run", tool),
        output,
        observation,
    )
}

pub(crate) fn fail_cli_tool_run_settled(
    target: &Path,
    run_id: &str,
    tool: &str,
    error: &str,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    completion: kuzushi_core::PendingToolCallCompletion,
) -> Result<()> {
    try_record_tool_run_failed_settled(
        ToolRunRecord::new(target, run_id, "run", tool),
        error,
        observation,
        completion,
    )
}

#[cfg(test)]
pub(crate) fn fail_cli_tool_run(target: &Path, run_id: &str, tool: &str, error: &str) {
    kuzushi_core::run_artifacts::record_tool_run_failed(
        ToolRunRecord::new(target, run_id, "run", tool),
        error,
    );
}

pub(crate) fn try_fail_cli_tool_run_observed(
    target: &Path,
    run_id: &str,
    tool: &str,
    error: &str,
    observation: Option<&kuzushi_core::run_lifecycle::RunObservationHandle>,
    execution_may_have_occurred: bool,
) -> Result<()> {
    try_record_tool_run_failed_observed_with_execution(
        ToolRunRecord::new(target, run_id, "run", tool),
        error,
        observation,
        execution_may_have_occurred,
    )
}
