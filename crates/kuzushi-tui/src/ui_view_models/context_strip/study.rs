use super::ShellApp;
use crate::{app::CampaignRouteState, ShellView};

pub(super) fn reader_title(app: &ShellApp) -> Option<&'static str> {
    study_reader(app)
        .map(selected_reader_title)
        .or_else(|| loading_history_title(app))
}

fn selected_reader_title(deck: &CampaignRouteState) -> &'static str {
    if deck.job_detail {
        "Study job"
    } else {
        "Study jobs"
    }
}

fn loading_history_title(app: &ShellApp) -> Option<&'static str> {
    if app.router.campaign().batch_scan_config.is_some() {
        return None;
    }
    (app.shell_view() == ShellView::Campaign && app.campaign_history_loading())
        .then_some("Investigation history")
}

fn study_reader(app: &ShellApp) -> Option<&CampaignRouteState> {
    if app.pending_campaign_selection().is_some() {
        return None;
    }
    let deck = (app.shell_view() == ShellView::Campaign).then(|| app.router.campaign())?;
    if !deck.detail || deck.batch_scan_config.is_some() {
        return None;
    }
    deck.selected_campaign()
        .filter(|row| crate::app::is_fixed_study_snapshot(row))?;
    Some(deck)
}
