use super::*;
use crate::ui_view_models::{ScanAttemptModel, ScanPhaseModel};

pub(super) fn receipt_status_lines(attempt: &ScanAttemptModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled(
            fit(
                &format!("outcome {} · {}", attempt.outcome, attempt.freshness),
                width,
            ),
            outcome_style(&attempt.outcome),
        ),
        Line::styled(
            fit(&format!("result {}", attempt.disposition), width),
            disposition_style(&attempt.disposition),
        ),
    ];
    if let Some(attempt_id) = attempt.attempt_id.as_deref() {
        lines.push(Line::styled(
            fit(&format!("attempt {attempt_id}"), width),
            theme::muted(),
        ));
    }
    lines
}

pub(super) fn receipt_reference_lines(
    attempt: &ScanAttemptModel,
    width: usize,
) -> Vec<Line<'static>> {
    let reference_count = attempt.run_refs.len();
    attempt
        .run_refs
        .iter()
        .enumerate()
        .map(|(index, run_ref)| {
            Line::styled(
                fit(
                    &format!("run {}/{} {run_ref}", index + 1, reference_count),
                    width,
                ),
                theme::primary(),
            )
        })
        .collect()
}

pub(super) fn receipt_metrics_lines(
    model: &ScanPhaseModel,
    attempt: &ScanAttemptModel,
    width: usize,
) -> Vec<Line<'static>> {
    vec![
        Line::styled(
            fit(
                &format!(
                    "duration {} · cost {}",
                    optional_duration(attempt.duration_secs),
                    optional_cost(attempt.cost_usd, attempt.cost_complete)
                ),
                width,
            ),
            theme::muted(),
        ),
        Line::styled(fit(&scan_rerun_command(model), width), theme::primary()),
    ]
}

fn scan_rerun_command(model: &ScanPhaseModel) -> String {
    model
        .engine_outcomes
        .iter()
        .find(|outcome| outcome.engine.contains(':'))
        .map(|outcome| format!("> run {} {{}}", outcome.engine))
        .unwrap_or_else(|| "> describe what to scan".to_string())
}

pub(super) fn compact_summary_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        fit(&format!("scope {}", model.scope), width),
        theme::primary(),
    )];
    if let Some(hint) = model.empty_hint.as_deref() {
        lines.push(Line::styled(fit(hint, width), theme::warn()));
    }
    lines.extend(compact_attempt_lines(model.attempt.as_ref(), width));
    lines.extend(compact_result_lines(model, width));
    lines
}

fn compact_result_lines(model: &ScanPhaseModel, width: usize) -> Vec<Line<'static>> {
    let Some(attempt) = model.attempt.as_ref() else {
        return vec![Line::styled(
            fit(
                &format!("engines {} recorded", model.engine_outcomes.len()),
                width,
            ),
            theme::muted(),
        )];
    };
    vec![
        Line::styled(
            fit(
                &format!(
                    "engines {} · {}",
                    model.engine_outcomes.len(),
                    compact_finding_delta(attempt),
                ),
                width,
            ),
            theme::primary(),
        ),
        Line::styled(fit(&attempt_reference_line(attempt), width), theme::muted()),
        Line::styled(
            fit(&format!("result {}", attempt.disposition), width),
            disposition_style(&attempt.disposition),
        ),
    ]
}

fn compact_attempt_lines(attempt: Option<&ScanAttemptModel>, width: usize) -> Vec<Line<'static>> {
    let Some(attempt) = attempt else {
        return vec![Line::styled("outcome not recorded", theme::muted())];
    };
    vec![Line::styled(
        fit(
            &format!("outcome {} · {}", attempt.outcome, attempt.freshness),
            width,
        ),
        outcome_style(&attempt.outcome),
    )]
}

pub(super) fn optional_count(value: Option<u64>) -> String {
    value
        .map(|count| count.to_string())
        .unwrap_or_else(|| "not recorded".to_string())
}

fn optional_duration(value: Option<u64>) -> String {
    value
        .map(|seconds| format!("{seconds}s"))
        .unwrap_or_else(|| "not recorded".to_string())
}

fn optional_cost(value: Option<f64>, complete: Option<bool>) -> String {
    match (value, complete) {
        (Some(cost), Some(false)) => format!(">=${cost:.4} incomplete"),
        (Some(cost), _) => format!("${cost:.4}"),
        (None, _) => "not recorded".to_string(),
    }
}

fn compact_finding_delta(attempt: &ScanAttemptModel) -> String {
    match (attempt.findings_added, attempt.findings_updated) {
        (Some(added), Some(updated)) => format!("findings +{added}/~{updated}"),
        _ => format!("findings {}", optional_count(attempt.findings)),
    }
}

fn short_run_id(run_id: &str) -> String {
    run_id.chars().take(12).collect()
}

fn attempt_reference_line(attempt: &ScanAttemptModel) -> String {
    let attempt_id = attempt
        .attempt_id
        .as_deref()
        .map(short_run_id)
        .map(|attempt| format!("attempt {attempt} · "))
        .unwrap_or_default();
    format!(
        "{attempt_id}run {}{}",
        short_run_id(&attempt.run_id),
        if attempt.run_refs.len() > 1 {
            format!(" +{} refs", attempt.run_refs.len() - 1)
        } else {
            String::new()
        }
    )
}

pub(super) fn outcome_symbol(outcome: &str) -> &'static str {
    match outcome {
        "complete" | "completed" => "✓",
        "partial" => "⚠",
        "failed" => "✗",
        "canceled" | "cancelled" | "interrupted" => "×",
        "skipped" => "⊘",
        _ => "○",
    }
}

pub(super) fn outcome_style(outcome: &str) -> ratatui::style::Style {
    match outcome {
        "complete" | "completed" => theme::success(),
        "partial" | "skipped" => theme::warn(),
        "failed" => theme::danger(),
        "canceled" | "cancelled" | "interrupted" => theme::muted(),
        _ => theme::primary(),
    }
}

pub(super) fn disposition_style(disposition: &str) -> ratatui::style::Style {
    if disposition.starts_with("selected") {
        theme::success()
    } else if disposition == "awaiting disposition" {
        theme::warn()
    } else {
        theme::muted()
    }
}
