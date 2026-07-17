use super::super::application::RunPresentationHydrationV1;
use super::super::{RunItemStatus, RunProjection, SafeText};
use std::path::Path;

pub(super) fn load_presentation_hydration(
    target: &Path,
    run_id: &str,
    projection: &RunProjection,
) -> RunPresentationHydrationV1 {
    let mut hydration = RunPresentationHydrationV1::default();
    for call_id in &projection.call_order {
        let Some(call) = projection.calls.get(call_id) else {
            continue;
        };
        let Some(reference) = call.result_artifact.as_ref() else {
            continue;
        };
        match crate::run_artifacts::load_correlated_run_result_summary(
            target,
            run_id,
            call.item_id,
            reference,
        ) {
            Ok(summary) if result_status_matches(call.status, &summary.status) => {
                hydration.insert_verified(call.item_id, summary);
            }
            Ok(_) => hydration.insert_unavailable(
                call.item_id,
                SafeText::operator_visible("correlated result status contradicts its call"),
            ),
            Err(error) => hydration.insert_unavailable(
                call.item_id,
                SafeText::operator_visible(format!(
                    "correlated result could not be verified: {error}"
                )),
            ),
        }
    }
    hydration
}

fn result_status_matches(status: RunItemStatus, result: &str) -> bool {
    match status {
        RunItemStatus::Completed => result == "completed",
        RunItemStatus::Partial => result == "partial",
        RunItemStatus::Skipped => result == "skipped",
        RunItemStatus::Failed => result == "failed",
        RunItemStatus::Canceled | RunItemStatus::Interrupted => result == "failed",
        RunItemStatus::Pending | RunItemStatus::Running => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_status_matching_is_exhaustive() {
        assert!(result_status_matches(RunItemStatus::Completed, "completed"));
        assert!(result_status_matches(RunItemStatus::Interrupted, "failed"));
        assert!(!result_status_matches(RunItemStatus::Partial, "completed"));
        assert!(!result_status_matches(RunItemStatus::Running, "completed"));
    }
}
