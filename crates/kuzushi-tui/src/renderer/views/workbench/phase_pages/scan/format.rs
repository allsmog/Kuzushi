use super::*;
use crate::ui_view_models::{ScanAttemptModel, ScanPhaseModel};

pub(super) fn receipt_status_lines(attempt: &ScanAttemptModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(
        fit(
            &format!("outcome {} · {}", attempt.outcome, attempt.freshness),
            width,
        ),
        outcome_style(&attempt.outcome),
    )];
    lines.extend(disposition_lines(&attempt.disposition, width));
    if let Some(attempt_id) = attempt.attempt_id.as_deref() {
        lines.push(Line::styled(
            fit(&format!("attempt {attempt_id}"), width),
            theme::muted(),
        ));
    }
    lines
}

fn disposition_lines(disposition: &str, width: usize) -> Vec<Line<'static>> {
    let full = format!("result {disposition}");
    let label = if display_width(&full) <= width {
        full
    } else {
        disposition.to_string()
    };
    crate::renderer::shared::text::wrap_text(&label, width)
        .into_iter()
        .map(|line| Line::styled(line, disposition_style(disposition)))
        .collect()
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
        Line::styled(fit(&scan_rerun_guidance(model), width), theme::primary()),
    ]
}

fn scan_rerun_guidance(model: &ScanPhaseModel) -> String {
    if model.attempt.is_some() {
        return "r Review saved scan options".into();
    }
    "> describe what to scan".into()
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
    let mut lines = vec![Line::styled(
        fit(
            &format!(
                "engines {} · {}",
                model.engine_outcomes.len(),
                compact_finding_delta(attempt),
            ),
            width,
        ),
        theme::primary(),
    )];
    if !attempt.severity_counts.is_empty() {
        lines.push(Line::styled(
            fit(&severity_chip_label(&attempt.severity_counts), width),
            severity_chip_style(&attempt.severity_counts),
        ));
    }
    lines.push(Line::styled(
        fit(&attempt_reference_line(attempt), width),
        theme::muted(),
    ));
    lines.push(Line::styled(
        fit(&format!("result {}", attempt.disposition), width),
        disposition_style(&attempt.disposition),
    ));
    lines
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
        (Some(0.0), Some(false)) => "unavailable (metering incomplete)".to_string(),
        (Some(cost), Some(false)) => format!(">=${cost:.4} incomplete"),
        (Some(cost), _) => format!("${cost:.4}"),
        (None, _) => "not recorded".to_string(),
    }
}

/// One chip per recorded severity band, highest first: "1 critical · 2 high".
pub(super) fn severity_chip_label(counts: &[(String, u64)]) -> String {
    counts
        .iter()
        .map(|(severity, count)| format!("{count} {severity}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// The line inherits the urgency of the worst band present.
pub(super) fn severity_chip_style(counts: &[(String, u64)]) -> ratatui::style::Style {
    if counts.iter().any(|(severity, _)| severity == "critical") {
        theme::danger()
    } else if counts.iter().any(|(severity, _)| severity == "high") {
        theme::warn()
    } else {
        theme::muted()
    }
}

fn compact_finding_delta(attempt: &ScanAttemptModel) -> String {
    match (attempt.findings_added, attempt.findings_updated) {
        (Some(added), Some(updated)) => format!("findings +{added}/~{updated}"),
        _ => match (attempt.findings, attempt.findings_observed) {
            (Some(findings), Some(observations)) => {
                format!("findings {findings} from {observations} obs")
            }
            _ => format!("findings {}", optional_count(attempt.findings)),
        },
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
        "blocked" | "refused" => "▣",
        "failed" => "✗",
        "canceled" | "cancelled" | "interrupted" | "stopped" => "×",
        "skipped" => "⊘",
        _ => "○",
    }
}

pub(super) fn outcome_style(outcome: &str) -> ratatui::style::Style {
    match outcome {
        "complete" | "completed" => theme::success(),
        "partial" | "blocked" | "refused" | "skipped" => theme::warn(),
        "failed" => theme::danger(),
        "canceled" | "cancelled" | "interrupted" | "stopped" => theme::muted(),
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

#[cfg(test)]
mod tests {
    use super::{compact_finding_delta, disposition_lines, ScanAttemptModel};

    #[test]
    fn receipt_rerun_guidance_keeps_the_owner_options_instead_of_an_empty_engine_command() {
        let model = super::ScanPhaseModel {
            study: None,
            scope: "2 exact source files".into(),
            plan: "saved selection".into(),
            engine_outcomes: Vec::new(),
            attempt: Some(attempt(Some(2), None)),
            empty_hint: None,
            live: None,
        };
        let text = super::scan_rerun_guidance(&model);
        assert!(text.contains("saved scan options"));
        assert!(!text.contains("run semgrep"));
        assert!(!text.contains("{}"));
    }

    #[test]
    fn acknowledged_partial_disposition_remains_readable_in_a_receipt_column() {
        let disposition = "selected · partial acknowledged";
        let column = disposition_lines(disposition, 35);
        assert_eq!(column[0].to_string(), disposition);
        for width in [18, 20, 35, 58, 118] {
            let lines = disposition_lines(disposition, width);
            assert!(lines.iter().all(|line| line.width() <= width));
            let text = lines
                .iter()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(text.contains(disposition), "{width}: {text}");
        }
    }

    #[test]
    fn unpriced_scan_never_displays_a_zero_dollar_total() {
        assert_eq!(
            super::optional_cost(Some(0.0), Some(false)),
            "unavailable (metering incomplete)"
        );
        assert_eq!(
            super::optional_cost(Some(0.25), Some(false)),
            ">=$0.2500 incomplete"
        );
        assert_eq!(super::optional_cost(Some(0.0), Some(true)), "$0.0000");
    }

    fn attempt(findings: Option<u64>, findings_observed: Option<u64>) -> ScanAttemptModel {
        ScanAttemptModel {
            attempt_id: None,
            run_id: "run-1".to_string(),
            run_refs: vec!["run-1".to_string()],
            outcome: "completed".to_string(),
            disposition: "selected".to_string(),
            freshness: "current revision".to_string(),
            findings,
            findings_observed,
            findings_added: None,
            findings_updated: None,
            severity_counts: Vec::new(),
            artifact_count: 0,
            artifact_paths: Vec::new(),
            duration_secs: None,
            cost_usd: None,
            cost_complete: None,
            error: None,
        }
    }

    /// The compact pane carries the same two quantities as the full delta
    /// panel, so a narrow terminal cannot be the one that reads the runs'
    /// observation count as the attempt's findings. Issue #172.
    #[test]
    fn compact_delta_names_the_observations_a_smaller_finding_count_folds() {
        assert_eq!(
            compact_finding_delta(&attempt(Some(25), Some(27))),
            "findings 25 from 27 obs"
        );
        assert_eq!(
            compact_finding_delta(&attempt(Some(25), None)),
            "findings 25"
        );
        assert_eq!(
            compact_finding_delta(&attempt(None, None)),
            "findings not recorded"
        );
    }
}
