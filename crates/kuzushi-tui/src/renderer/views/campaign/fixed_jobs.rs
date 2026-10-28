//! Human case/pass labels and recorded job detail for finite investigations.
use super::*;
use crate::app::CampaignRouteState;
use kuzushi_core::capabilities::campaign::snapshot::{CampaignJobSnapshot, CampaignSnapshot};

pub(super) fn append_fixed_jobs(
    lines: &mut Vec<Line<'static>>,
    deck: &CampaignRouteState,
    campaign: &CampaignSnapshot,
    width: usize,
) {
    lines.push(muted("Fixed jobs · recorded state and attempts"));
    for (index, job) in campaign.jobs.iter().enumerate() {
        append_job_row(lines, job, index == deck.selected_job, width);
    }
    super::campaign_lines::append_attempt_count_hint(lines, campaign, width);
}

fn append_job_row(
    lines: &mut Vec<Line<'static>>,
    job: &CampaignJobSnapshot,
    selected: bool,
    width: usize,
) {
    let marker = if selected { "▸" } else { " " };
    let (name, pass) = job_label_parts(job);
    let style = super::campaign_lines::job_state_style(&job.state);
    let state = crate::ui_view_models::campaign_job_state_label(job);
    let usage = crate::ui_view_models::campaign_job_attempt_summary(job);
    if width < 80 {
        lines.push(styled(
            &format!(
                "{marker} {}",
                fitted_job_label(name, pass, width.saturating_sub(2))
            ),
            theme::primary(),
        ));
        let state_width = width.saturating_sub(display_width(&usage) + 5);
        let status = format!("  {} · {usage}", fit(state, state_width));
        lines.push(styled(&fit(&status, width), style));
        return;
    }
    let label_width = width.saturating_sub(display_width(&usage) + 22);
    let text = format!(
        "{marker} {}  {}  {usage}",
        pad(&fitted_job_label(name, pass, label_width), label_width),
        pad(&fit(state, 16), 16),
    );
    lines.push(styled(&fit(&text, width), style));
}

fn job_label_parts(job: &CampaignJobSnapshot) -> (&str, Option<&str>) {
    if let Some((name, pass)) = job
        .display_label
        .as_deref()
        .and_then(|label| label.rsplit_once(" · pass "))
    {
        return (name, Some(pass));
    }
    (job.display_label.as_deref().unwrap_or(&job.job_id), None)
}

fn fitted_job_label(name: &str, pass: Option<&str>, width: usize) -> String {
    let Some(pass) = pass else {
        return fit(name, width);
    };
    let suffix = format!(" · pass {pass}");
    format!(
        "{}{suffix}",
        fit(name, width.saturating_sub(display_width(&suffix)))
    )
}

pub(super) fn selected_job_heading(job: &CampaignJobSnapshot, width: usize) -> String {
    let (name, pass) = job_label_parts(job);
    fit(
        &format!(
            "Job: {}",
            fitted_job_label(name, pass, width.saturating_sub(5))
        ),
        width,
    )
}

pub(super) fn append_selected_detail(
    lines: &mut Vec<Line<'static>>,
    job: &CampaignJobSnapshot,
    width: usize,
) {
    lines.push(blank());
    lines.push(divider("SELECTED JOB", width as u16));
    for text in crate::ui_view_models::campaign_job_detail_lines(job) {
        push_deck_text(lines, &text, width, theme::primary());
    }
    push_deck_text(lines, "These are recorded job inputs. a reviews the fixed plan, source/context receipts and allowance; reading approves nothing.", width, theme::muted());
}
