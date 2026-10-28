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
        let tool = job.tool.as_deref().unwrap_or("tool unavailable");
        lines.push(job_state_line(marker, tool, &job.state, width));
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

/// `▸ tool · state` with the state in its campaign job colour.
fn job_state_line(marker: &str, tool: &str, state: &str, width: usize) -> Line<'static> {
    let head = fit(
        &format!("{marker} {tool} · "),
        width.saturating_sub(state.chars().count()).max(1),
    );
    Line::from(vec![
        Span::styled(head, theme::primary()),
        Span::styled(
            state.to_owned(),
            super::campaign_lines::job_state_style(state),
        ),
    ])
}
