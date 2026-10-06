use super::*;
use kuzushi_core::capabilities::campaign::{load_named_scan_usage, load_scan_usage_catalogue};

pub(super) fn read_study_usage(
    target: &Path,
    key: &ViewHydrationKey,
    cancellation: &ViewHydrationCancellation,
) -> Option<Option<ViewHydrationValue>> {
    match key {
        ViewHydrationKey::StudyUsageCatalogue => Some(read_catalogue(target, cancellation)),
        ViewHydrationKey::StudyUsageRun { run_id } => {
            let value = load_named_scan_usage(target, run_id).map_err(|error| error.to_string());
            Some((!cancellation.is_canceled()).then_some(ViewHydrationValue::StudyUsageRun(value)))
        }
        _ => None,
    }
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
