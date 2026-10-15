use crate::app::ShellApp;
use kuzushi_core::capabilities::campaign::snapshot::CampaignJobSnapshot;

pub(crate) fn context_result_jobs(app: &ShellApp) -> Vec<CampaignJobSnapshot> {
    let Some(config) = app.router.campaign().batch_scan_config.as_ref() else {
        return Vec::new();
    };
    let Some(receipt) = config.study.receipt.as_ref() else {
        return Vec::new();
    };
    app.router
        .campaign()
        .campaigns
        .iter()
        .find(|campaign| campaign.campaign_id == receipt.campaign_id)
        .map(|campaign| campaign.jobs.clone())
        .unwrap_or_default()
}

pub(crate) fn context_result_lines(app: &ShellApp, width: usize, rows: usize) -> Vec<String> {
    let Some(config) = app.router.campaign().batch_scan_config.as_ref() else {
        return crate::renderer::shared::text::wrap_text(
            "No study selected. Open a study from Campaigns to compare its passes.",
            width.max(1),
        );
    };
    let selected = config.context_result_cursor.unwrap_or(0);
    let jobs = context_result_jobs(app);
    let mut lines = vec![
        "Choose a candidate pass.".into(),
        "Comparison leaves decisions unchanged.".into(),
    ];
    lines.extend(config.notice.iter().cloned());
    let mut lines = lines
        .into_iter()
        .flat_map(|line| crate::renderer::shared::text::wrap_text(&line, width.max(1)))
        .collect::<Vec<_>>();
    let count = rows.saturating_sub(lines.len()).max(1);
    let start = selected.saturating_sub(count.saturating_sub(1));
    for (index, job) in jobs.iter().enumerate().skip(start).take(count) {
        lines.push(format!(
            "{} Pass {} · {}",
            if index == selected { "▸" } else { " " },
            index + 1,
            job.state
        ));
    }
    if jobs.is_empty() {
        lines.push("Candidate runs are not loaded. Refresh the campaign before comparing.".into());
    }
    lines
}
