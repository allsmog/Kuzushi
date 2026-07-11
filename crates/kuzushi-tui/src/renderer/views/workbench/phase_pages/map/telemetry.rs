use super::*;

pub(super) fn telemetry_lines(
    model: &MapPhaseModel,
    header: &EngagementHeaderModel,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        progress_line(&model.task_counts, width),
        budget_line(model, header, width),
        task_count_line(&model.task_counts, width),
    ];
    if !model.artifact_metrics.is_empty() {
        lines.push(artifact_metric_line(&model.artifact_metrics, width));
    }
    lines
}

fn artifact_metric_line(metrics: &[MapArtifactMetric], width: usize) -> Line<'static> {
    let text = metrics
        .iter()
        .fold("artifacts".to_string(), |mut line, metric| {
            let candidate = format!("{line} · {} {}", metric.label, metric.value);
            if display_width(&candidate) <= width {
                line = candidate;
            }
            line
        });
    Line::styled(text, theme::primary())
}

fn progress_line(counts: &ActivityTaskCountModel, width: usize) -> Line<'static> {
    meter_line(
        "coverage",
        ratio(counts.completed, counts.total),
        &format!("{} / {} tasks", counts.completed, counts.total),
        width,
        theme::accent(),
    )
}

fn budget_line(
    model: &MapPhaseModel,
    header: &EngagementHeaderModel,
    width: usize,
) -> Line<'static> {
    let spent = model.run_cost_usd.max(header.cost_usd);
    let Some(cap) = header.budget_usd.filter(|cap| *cap > 0.0) else {
        return Line::styled(
            fit(&format!("budget    ${spent:.4} · no session cap"), width),
            theme::muted(),
        );
    };
    meter_line(
        "budget",
        (spent / cap).clamp(0.0, 1.0),
        &format!("${spent:.2} / ${cap:.2}"),
        width,
        budget_style(spent / cap),
    )
}

fn meter_line(
    label: &str,
    ratio: f64,
    value: &str,
    width: usize,
    style: ratatui::style::Style,
) -> Line<'static> {
    let available = width.saturating_sub(label.len() + value.len() + 5);
    let max_meter_width = if width >= 120 {
        72
    } else if width >= 80 {
        40
    } else {
        28
    };
    let meter_width = available.clamp(6, max_meter_width);
    let filled = ((meter_width as f64 * ratio).round() as usize).min(meter_width);
    Line::from(vec![
        Span::styled(format!("{label:<10}"), theme::muted()),
        Span::styled("█".repeat(filled), style),
        Span::styled("░".repeat(meter_width - filled), theme::subtle()),
        Span::raw("  "),
        Span::styled(value.to_string(), theme::primary()),
    ])
}

pub(super) fn task_count_line(counts: &ActivityTaskCountModel, width: usize) -> Line<'static> {
    let atoms = [
        format!("active {}", counts.active),
        format!("canceling {}", counts.canceling),
        format!("failed {}", counts.failed),
        format!("blocked {}", counts.blocked),
        format!("canceled {}", counts.canceled),
        format!("skipped {}", counts.skipped),
    ];
    let text = atoms.iter().fold("tasks".to_string(), |mut line, atom| {
        let candidate = format!("{line} · {atom}");
        if display_width(&candidate) <= width {
            line = candidate;
        }
        line
    });
    Line::styled(text, theme::muted())
}

fn budget_style(ratio: f64) -> ratatui::style::Style {
    if ratio >= 0.9 {
        theme::danger()
    } else if ratio >= 0.7 {
        theme::warn()
    } else {
        theme::accent()
    }
}

fn ratio(value: usize, total: usize) -> f64 {
    (total > 0)
        .then(|| value as f64 / total as f64)
        .unwrap_or_default()
}
