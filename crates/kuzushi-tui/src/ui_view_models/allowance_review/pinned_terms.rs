use crate::renderer::shared::text::{fit, wrap_text};
use crate::ShellApp;
use serde_json::Value;

pub(super) fn lines(app: &ShellApp, width: usize, max_rows: usize) -> Vec<String> {
    let Some(launch) = app.advisory().pending_confirm_launch.as_ref() else {
        return Vec::new();
    };
    if launch.tool_name != "campaign:approve-allowance" {
        return Vec::new();
    }
    let input = launch.input.value();
    let mut lines = work_line(app, input, width).into_iter().collect::<Vec<_>>();
    lines.push(limit_line(input, width));
    let model = input["model"].as_str().unwrap_or("unavailable");
    lines.push(fit(
        &format!("Allowance: {}", crate::app::display_model_selector(model)),
        width,
    ));
    let mut pinned = wrap_lines(lines, width);
    let accounting = wrap_lines(accounting_lines(app, input, width), width);
    if pinned.len() + accounting.len() <= max_rows {
        pinned.extend(accounting);
    }
    pinned
}

fn wrap_lines(lines: Vec<String>, width: usize) -> Vec<String> {
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width))
        .collect()
}

fn accounting_lines(app: &ShellApp, input: &Value, width: usize) -> Vec<String> {
    let Some(snapshot) = crate::allowance::revised_snapshot(app, input) else {
        return Vec::new();
    };
    let used = snapshot.committed_calls;
    let unsettled = snapshot.unresolved_calls;
    let scan = snapshot.remaining_discovery_calls();
    let review = snapshot.protected_review_remaining();
    if width < 72 {
        return vec![format!("Used {used} · left Scan {scan} Review {review}")];
    }
    vec![
        format!("Recorded calls: {used} committed · {unsettled} unsettled"),
        format!("Left under proposed limits: {scan} context/scan · {review} protected Review"),
    ]
}

fn work_line(app: &ShellApp, input: &Value, width: usize) -> Option<String> {
    input["campaignId"].as_str()?;
    let workers = super::allowance_work_summary(app, input)
        .and_then(|summary| summary.workers)
        .map_or_else(|| "unknown".into(), |value| value.to_string());
    let jobs = number(input, "campaignJobs");
    let attempts = number(input, "maxJobAttempts");
    Some(if width < 72 {
        format!("{jobs} jobs · workers {workers} · attempts {attempts}")
    } else {
        format!("{jobs} fixed jobs · {workers} worker(s) · {attempts} attempt(s) each")
    })
}

fn limit_line(input: &Value, width: usize) -> String {
    let calls = number(input, "maxProviderCalls");
    let review = number(input, "protectedReviewCalls");
    if width < 72 {
        return format!("Total calls {calls} · Review reserve {review}");
    }
    format!("Total provider calls: {calls} · Protected review calls: {review}")
}

fn number(input: &Value, key: &str) -> String {
    input[key]
        .as_u64()
        .map_or_else(|| "unknown".into(), |value| value.to_string())
}
