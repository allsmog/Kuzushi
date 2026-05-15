use super::ReportFailureHandoff;
use crate::run_artifacts::{load_run_failures, FailureToLlmContext};
use std::path::Path;

pub(super) fn load_report_failure_handoffs(
    target: &Path,
    run_id: &str,
) -> Vec<ReportFailureHandoff> {
    let Ok(report) = load_run_failures(target, run_id) else {
        return Vec::new();
    };
    report
        .failures
        .into_iter()
        .map(|failure| failure_handoff_summary(failure.agent_thread_context))
        .collect()
}

fn failure_handoff_summary(context: FailureToLlmContext) -> ReportFailureHandoff {
    ReportFailureHandoff {
        failed_stage: context.failed_stage,
        cause: context.cause,
        artifacts_available: context.artifacts_available,
        allowed_proof_level: context.allowed_proof_level,
        missing_artifacts: context.missing_artifacts,
        next_files_or_artifacts_to_inspect: context.next_files_or_artifacts_to_inspect,
        recovery_options: context.recovery_options,
        fallback_prompt: context.fallback_prompt,
        claims_forbidden: context.claims_forbidden,
    }
}
