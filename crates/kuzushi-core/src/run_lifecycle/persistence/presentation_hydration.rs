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
    if result == "failed" {
        // Older receipts used one failed envelope for these terminal outcomes.
        return matches!(
            status,
            RunItemStatus::Blocked
                | RunItemStatus::Failed
                | RunItemStatus::Canceled
                | RunItemStatus::Interrupted
        );
    }
    status.is_terminal() && status.label() == result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_status_matching_is_exhaustive() {
        let cases: &[(RunItemStatus, &[&str])] = &[
            (RunItemStatus::Pending, &[]),
            (RunItemStatus::Running, &[]),
            (RunItemStatus::Completed, &["completed"]),
            (RunItemStatus::Partial, &["partial"]),
            (RunItemStatus::Skipped, &["skipped"]),
            (RunItemStatus::Blocked, &["blocked", "failed"]),
            (RunItemStatus::Failed, &["failed"]),
            (RunItemStatus::Canceled, &["canceled", "failed"]),
            (RunItemStatus::Interrupted, &["interrupted", "failed"]),
        ];
        for (status, accepted) in cases {
            for result in [
                "pending",
                "running",
                "completed",
                "partial",
                "skipped",
                "blocked",
                "failed",
                "canceled",
                "interrupted",
                "unknown",
                "",
            ] {
                assert_eq!(
                    result_status_matches(*status, result),
                    accepted.contains(&result),
                    "{status:?}: {result}"
                );
            }
        }
    }
}
