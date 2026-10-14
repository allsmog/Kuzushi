use super::*;
use kuzushi_core::capabilities::campaign::{load_named_scan_usage, load_scan_usage_catalogue};

pub(super) fn read_study_usage(
    target: &Path,
    key: &ViewHydrationKey,
    cancellation: &ViewHydrationCancellation,
) -> Option<Option<ViewHydrationValue>> {
    match key {
        ViewHydrationKey::ContextMatrixReport {
            campaign_id,
            plan_sha256,
        } => {
            let value = read_matrix_report(target, campaign_id, plan_sha256);
            Some(
                (!cancellation.is_canceled())
                    .then_some(ViewHydrationValue::ContextMatrixReport(value)),
            )
        }
        ViewHydrationKey::StudyUsageCatalogue => Some(read_catalogue(target, cancellation)),
        ViewHydrationKey::StudyHistory => Some(read_study_history(target, cancellation)),
        ViewHydrationKey::StudyUsageRun { run_id } => {
            let value = load_named_scan_usage(target, run_id).map_err(|error| error.to_string());
            Some((!cancellation.is_canceled()).then_some(ViewHydrationValue::StudyUsageRun(value)))
        }
        _ => None,
    }
}

fn read_study_history(
    target: &Path,
    cancellation: &ViewHydrationCancellation,
) -> Option<ViewHydrationValue> {
    match kuzushi_core::capabilities::campaign::load_study_usage_catalogue(target, &|| {
        cancellation.is_canceled()
    }) {
        Ok(None) => None,
        Ok(Some(value)) => Some(ViewHydrationValue::StudyHistory(Ok(value))),
        Err(error) => Some(ViewHydrationValue::StudyHistory(Err(error.to_string()))),
    }
}

fn read_matrix_report(
    target: &Path,
    id: &str,
    digest: &str,
) -> Result<kuzushi_core::findings::ContextMatrixOccurrenceReport, String> {
    let report = kuzushi_core::findings::read_context_matrix_occurrence_report(target, id)
        .map_err(|error| format!("{error:#}"))?;
    if report.plan_sha256 != digest {
        return Err("Context matrix changed; refresh the saved plan before reading results".into());
    };
    Ok(report)
}

fn read_catalogue(
    target: &Path,
    cancellation: &ViewHydrationCancellation,
) -> Option<ViewHydrationValue> {
    match load_scan_usage_catalogue(target, &|| cancellation.is_canceled()) {
        Ok(None) => None,
        Ok(Some(value)) => Some(ViewHydrationValue::StudyUsageCatalogue(Ok(value))),
        Err(error) => Some(ViewHydrationValue::StudyUsageCatalogue(Err(
            error.to_string()
        ))),
    }
}
