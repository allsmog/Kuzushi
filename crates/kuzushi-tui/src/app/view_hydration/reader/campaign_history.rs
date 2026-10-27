use super::*;
use crate::app::campaign::history_refresh::{
    CampaignHistoryReadRequest, CampaignHistoryReadSnapshot, CampaignPhaseRead,
};
use kuzushi_core::capabilities::campaign::history::{
    load_campaign_history, CampaignHistory, CampaignHistoryCoverage,
};

pub(super) fn read(
    target: &Path,
    key: &ViewHydrationKey,
    cancellation: &ViewHydrationCancellation,
) -> Option<Option<ViewHydrationValue>> {
    let ViewHydrationKey::CampaignHistory(request) = key else {
        return None;
    };
    Some(
        load(target, request, cancellation)
            .map(|snapshot| ViewHydrationValue::CampaignHistory(Arc::new(snapshot))),
    )
}

fn load(
    target: &Path,
    request: &CampaignHistoryReadRequest,
    cancellation: &ViewHydrationCancellation,
) -> Option<CampaignHistoryReadSnapshot> {
    let history = match load_campaign_history(target, request.preferred.as_deref(), &|| {
        cancellation.is_canceled()
    }) {
        Ok(history) => history?,
        Err(error) => unavailable_history(error),
    };
    if cancellation.is_canceled() {
        return None;
    }
    let trend = request.decisions.metrics().with_spend(history.spend());
    let trend_history = crate::app::campaign::refresh_trend_history(target, &trend);
    if cancellation.is_canceled() {
        return None;
    }
    let phase = Some(read_phase(target));
    (!cancellation.is_canceled()).then_some(CampaignHistoryReadSnapshot {
        history,
        phase,
        trend_history,
    })
}

fn read_phase(target: &Path) -> CampaignPhaseRead {
    CampaignPhaseRead {
        snapshot: kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target),
        recovered: kuzushi_core::workflow_attempts::load_phase_attempt_ledger_recovering(target)
            .map_err(|error| error.to_string()),
    }
}

fn unavailable_history(error: anyhow::Error) -> CampaignHistory {
    CampaignHistory {
        coverage: CampaignHistoryCoverage {
            directory_unreadable: true,
            ..Default::default()
        },
        requested_error: Some(format!("Investigation history unavailable: {error:#}")),
        ..Default::default()
    }
}
