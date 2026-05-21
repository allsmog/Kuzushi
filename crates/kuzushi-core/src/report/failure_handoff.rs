use super::ReportFailureHandoff;
use crate::run_artifacts::{load_run_failures, run_dir, RunFailure};
use anyhow::Result;
use std::path::Path;

pub(super) fn load_report_failure_handoffs(
    target: &Path,
    run_id: &str,
) -> Result<Vec<ReportFailureHandoff>> {
    if !run_dir(target, run_id).join("failures.json").exists() {
        return Ok(Vec::new());
    }
    Ok(load_run_failures(target, run_id)?
        .failures
        .into_iter()
        .map(failure_handoff_summary)
        .collect())
}

fn failure_handoff_summary(failure: RunFailure) -> ReportFailureHandoff {
    let context = failure.agent_thread_context;
    ReportFailureHandoff {
        failed_stage: fallback_string(context.failed_stage, failure.tool),
        cause: fallback_string(context.cause, failure.error),
        artifacts_available: context.artifacts_available,
        allowed_proof_level: context.allowed_proof_level,
        missing_artifacts: context.missing_artifacts,
        next_files_or_artifacts_to_inspect: context.next_files_or_artifacts_to_inspect,
        recovery_options: context.recovery_options,
        fallback_prompt: context.fallback_prompt,
        claims_forbidden: context.claims_forbidden,
    }
}

fn fallback_string(primary: String, fallback: String) -> String {
    if primary.trim().is_empty() {
        fallback
    } else {
        primary
    }
}
