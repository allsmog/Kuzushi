//! Recorded workload remains visible while the campaign document is paged.
use super::*;
use crate::app::CampaignRouteState;

pub(super) fn reader_heading(
    deck: &CampaignRouteState,
    start: usize,
    end: usize,
    total: usize,
    width: usize,
) -> String {
    let position = format!("rows {}-{end}/{total}", start + 1);
    let Some(campaign) = deck.selected_campaign().filter(|_| deck.detail) else {
        return fit(&format!(" {position} · PgUp/PgDn"), width);
    };
    let counts = super::summary::job_count_label(campaign);
    let detailed = format!("{counts} · {position}");
    let suffix = " · PgUp/PgDn";
    let available = width.saturating_sub(display_width(suffix));
    let summary = if display_width(&detailed) <= available {
        detailed
    } else {
        fit(&counts, available)
    };
    fit(&format!("{summary}{suffix}"), width)
}
