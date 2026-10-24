/// A queued current attempt has not published the receipts needed for a study read.
/// This does not establish process liveness or authenticate any findings.
#[derive(Debug)]
pub struct BatchReceiptPending;

impl std::fmt::Display for BatchReceiptPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Study attempt receipt is pending publication")
    }
}

impl std::error::Error for BatchReceiptPending {}

pub(super) fn current_attempt_error(
    trial: &super::BatchTrialReport,
    run_id: &str,
    artifact: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    if !is_current_running_attempt(trial, run_id) {
        return error;
    }
    if !is_missing_attempt_artifact(&error, run_id, artifact) {
        return error;
    }
    BatchReceiptPending.into()
}

pub(super) fn child_receipt_error(
    trial: &super::BatchTrialReport,
    run_id: &str,
    summary: &crate::run_artifacts::RunSummary,
    error: anyhow::Error,
) -> anyhow::Error {
    if summary.status != "running" {
        return error;
    }
    current_attempt_error(trial, run_id, "batch-equivalence.json", error)
}

fn is_missing_attempt_artifact(error: &anyhow::Error, run_id: &str, artifact: &str) -> bool {
    error
        .downcast_ref::<crate::run_artifacts::RunArtifactMissing>()
        .is_some_and(|missing| {
            missing
                .path()
                .ends_with(std::path::Path::new(run_id).join(artifact))
        })
}

fn is_current_running_attempt(trial: &super::BatchTrialReport, run_id: &str) -> bool {
    trial.state == "running" && trial.run_id.as_deref() == Some(run_id)
}
