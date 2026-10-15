use super::*;
use crate::app::CampaignRouteState;
use kuzushi_core::capabilities::campaign::snapshot::CampaignSnapshot;

pub(super) fn append_context_jobs(
    lines: &mut Vec<Line<'static>>,
    deck: &CampaignRouteState,
    campaign: &CampaignSnapshot,
    width: usize,
) {
    lines.push(muted("Fixed order · one attempt per job"));
    for (index, job) in campaign.jobs.iter().enumerate() {
        let marker = if index == deck.selected_job {
            "▸"
        } else {
            " "
        };
        let label = format!(
            "{} · {}",
            job.tool.as_deref().unwrap_or("tool unavailable"),
            job.state
        );
        lines.extend(marked_lines(&label, marker, width));
    }
    if let Some(job) = campaign.jobs.get(deck.selected_job) {
        let detail = format!(
            "  {} · {} · cost {}",
            job.job_id,
            crate::ui_view_models::campaign_job_attempt_summary(job),
            super::campaign_lines::job_cost_label(job)
        );
        lines.extend(
            wrap_text(&detail, width.max(1))
                .into_iter()
                .map(|line| muted(&line)),
        );
    }
    super::campaign_lines::append_attempt_count_hint(lines, campaign, width);
}

fn marked_lines(text: &str, marker: &str, width: usize) -> Vec<Line<'static>> {
    wrap_text(text, width.saturating_sub(2).max(1))
        .into_iter()
        .enumerate()
        .map(|(index, line)| {
            let marker = if index == 0 { marker } else { " " };
            styled(&format!("{marker} {line}"), theme::primary())
        })
        .collect()
}
