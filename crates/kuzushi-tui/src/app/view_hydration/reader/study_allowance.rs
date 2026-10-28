//! Read the current shared ledger only after authenticating the displayed plan.
use super::*;

pub(super) fn read(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    let ViewHydrationKey::StudyAllowance {
        campaign_id,
        plan_sha256,
    } = key
    else {
        return None;
    };
    let result = kuzushi_core::capabilities::campaign::load_fixed_study_allowance(
        target,
        campaign_id,
        plan_sha256,
    )
    .map(|snapshot| snapshot.map(Arc::new))
    .map_err(|error| format!("{error:#}"));
    Some(ViewHydrationValue::InvestigationAllowance(result))
}

#[cfg(test)]
mod tests;
