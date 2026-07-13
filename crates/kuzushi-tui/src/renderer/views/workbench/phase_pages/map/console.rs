use super::*;

pub(super) fn console_lines(
    model: &MapPhaseModel,
    width: usize,
    row_budget: usize,
) -> Vec<Line<'static>> {
    if model.console.is_empty() {
        return vec![empty_console_line(model, width)];
    }
    let start = model.console.len().saturating_sub(row_budget.max(1));
    let mut lines = earlier_rows_line(model, start, width)
        .into_iter()
        .collect::<Vec<_>>();
    lines.extend(
        model
            .console
            .iter()
            .skip(start)
            .map(|row| console_line(row, width)),
    );
    lines
}

fn empty_console_line(model: &MapPhaseModel, width: usize) -> Line<'static> {
    Line::styled(
        fit(
            model.empty_hint.unwrap_or("no trace events recorded"),
            width,
        ),
        theme::muted(),
    )
}

fn earlier_rows_line(model: &MapPhaseModel, start: usize, width: usize) -> Option<Line<'static>> {
    let hidden = model.hidden_console_rows + start;
    (hidden > 0).then(|| {
        Line::styled(
            fit(&format!(" … {hidden} earlier trace rows"), width),
            theme::subtle(),
        )
    })
}

fn console_line(row: &MapConsoleRow, width: usize) -> Line<'static> {
    let scope = match (row.module.as_deref(), row.verb.as_deref()) {
        (Some(module), Some(verb)) => format!("{module}:{verb}"),
        (Some(module), None) => module.to_string(),
        _ => row.kind.clone(),
    };
    let lead = console_row_lead(row, width);
    let body = format!("{lead}  {scope}  {}{}", row.label, row_metrics(row));
    Line::styled(fit(&body, width), console_style(row))
}

fn console_row_lead(row: &MapConsoleRow, width: usize) -> String {
    if width >= 80 {
        if let Some(timestamp) = row.started_at_ms {
            return clock_time(timestamp);
        }
    }
    format!("{:>4}", row.sequence)
}

fn clock_time(timestamp_ms: u64) -> String {
    let millis = timestamp_ms % 1_000;
    let seconds = timestamp_ms / 1_000;
    let second = seconds % 60;
    let minute = (seconds / 60) % 60;
    let hour = (seconds / 3_600) % 24;
    format!("{hour:02}:{minute:02}:{second:02}.{millis:03}")
}

fn row_metrics(row: &MapConsoleRow) -> String {
    let mut metrics = Vec::new();
    if let Some(latency) = row.latency_ms {
        metrics.push(format!("{latency}ms"));
    }
    if row.cost_invalid {
        metrics.push("cost invalid".to_string());
    } else if let Some(cost) = row.cost_usd.filter(|cost| *cost > 0.0) {
        metrics.push(format!("${cost:.4}"));
    }
    (!metrics.is_empty())
        .then(|| format!(" · {}", metrics.join(" · ")))
        .unwrap_or_default()
}

fn console_style(row: &MapConsoleRow) -> ratatui::style::Style {
    match row
        .severity
        .as_deref()
        .unwrap_or(&row.kind)
        .to_ascii_lowercase()
        .as_str()
    {
        "critical" | "high" | "failed" | "error" => theme::danger(),
        "warning" | "warn" | "refused" => theme::warn(),
        "done" | "complete" | "completed" | "success" => theme::success(),
        "tool" | "tool-start" | "tool-progress" => theme::accent(),
        _ => theme::primary(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_console_rows_render_real_trace_timestamps() {
        let row = MapConsoleRow {
            sequence: 7,
            started_at_ms: Some(3_723_045),
            kind: "tool-progress".to_string(),
            label: "mapped boundary".to_string(),
            module: Some("context".to_string()),
            verb: Some("build".to_string()),
            severity: None,
            latency_ms: Some(12),
            cost_usd: None,
            cost_invalid: false,
        };

        let text = console_line(&row, 120).to_string();
        assert!(text.contains("01:02:03.045"), "{text}");
    }

    #[test]
    fn invalid_console_cost_is_explicit() {
        let row = MapConsoleRow {
            sequence: 1,
            started_at_ms: None,
            kind: "reasoning".to_string(),
            label: "provider response".to_string(),
            module: Some("sast".to_string()),
            verb: Some("scan".to_string()),
            severity: None,
            latency_ms: None,
            cost_usd: None,
            cost_invalid: true,
        };

        let text = console_line(&row, 120).to_string();
        assert!(text.contains("cost invalid"), "{text}");
        assert!(!text.contains("inf"), "{text}");
    }
}
