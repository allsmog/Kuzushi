use super::ShellApp;
use crate::{app::CampaignRouteState, ShellView};

pub(super) fn reader_title(app: &ShellApp) -> Option<&'static str> {
    let deck = study_reader(app)?;
    Some(if deck.job_detail {
        "Study job"
    } else {
        "Study jobs"
    })
}

fn study_reader(app: &ShellApp) -> Option<&CampaignRouteState> {
    let deck = (app.shell_view() == ShellView::Campaign).then(|| app.router.campaign())?;
    if !deck.detail || deck.batch_scan_config.is_some() {
        return None;
    }
    deck.selected_campaign()
        .filter(|row| crate::app::is_fixed_study_snapshot(row))?;
    Some(deck)
}
