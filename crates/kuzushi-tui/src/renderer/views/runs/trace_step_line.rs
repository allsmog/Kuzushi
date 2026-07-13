use super::*;
use crate::ui_view_models::{alias_reference_model, TraceStep};

pub(crate) fn trace_step_line(step: &TraceStep, width: u16) -> Line<'static> {
    let label = trace_step_label(step);
    let label_budget = (width as usize).saturating_sub(28).max(20);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{:>3} ", step.n), theme::subtle()),
        Span::styled(format!("{:8}", step.kind), trace_kind_style(step)),
        Span::raw(" "),
        Span::styled(fit(&label, label_budget), theme::primary()),
        Span::raw("  "),
        Span::styled(format!("{:>7}", trace_latency_label(step)), theme::muted()),
        Span::raw("  "),
        Span::styled(trace_cost_label(step), theme::muted()),
    ])
}

fn trace_kind_style(step: &TraceStep) -> Style {
    match step.severity.as_deref() {
        Some("danger") => theme::danger(),
        Some("warn") => theme::warn(),
        _ => trace_kind_default_style(&step.kind),
    }
}

fn trace_kind_default_style(kind: &str) -> Style {
    match kind {
        "plan" => theme::label(),
        "tool" | "tool-start" => theme::success(),
        "done" | "tool-complete" => theme::success(),
        "llm" | "reasoning" | "tool-progress" => theme::accent(),
        "refused" | "failing" => theme::danger(),
        "critic" => theme::warn(),
        _ => theme::muted(),
    }
}

fn trace_latency_label(step: &TraceStep) -> String {
    step.latency_ms
        .map(format_latency)
        .unwrap_or_else(|| "—".to_string())
}

fn format_latency(ms: u64) -> String {
    if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{ms}ms")
    }
}

fn trace_cost_label(step: &TraceStep) -> String {
    step.cost_usd
        .map(|cost| format!("${cost:.4}"))
        .unwrap_or_else(|| "—".to_string())
}

fn trace_step_label(step: &TraceStep) -> String {
    let prefix = match (step.module_id.as_deref(), step.verb.as_deref()) {
        (Some(module), Some(verb)) => Some(format!("[{module}:{verb}]")),
        (Some(module), None) => Some(format!("[{module}]")),
        _ => None,
    };
    let indent = if step.parent_step.is_some() {
        "↳ "
    } else {
        ""
    };
    match prefix {
        Some(prefix) => format!("{indent}{prefix} {}", step.label),
        None => format!("{indent}{}", step.label),
    }
}

pub(crate) fn alias_reference_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let model = alias_reference_model(app);
    lines.push(blank());
    if model.rows.is_empty() {
        lines.push(muted(model.empty_message));
        return lines;
    }
    lines.push(divider("ALIASES", area.width));
    for row in model.rows {
        lines.push(detail(&row.alias, &row.detail));
    }
    if model.overflow_count > 0 {
        lines.push(muted(&fit(
            &format!(
                "  +{} more aliases · findings to view all",
                model.overflow_count
            ),
            area.width as usize,
        )));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Finding, Severity, V2Config};

    #[test]
    fn alias_reference_lines_disclose_overflow() {
        let mut app = ShellApp::new(V2Config::default(), None);
        *app.findings_mut() = (0..5)
            .map(|index| {
                Finding::new_semgrep(
                    format!("demo.rule.{index}"),
                    "src/app.rs",
                    index + 1,
                    None,
                    Severity::High,
                    format!("finding {index}"),
                )
            })
            .collect();

        let text = alias_reference_lines(&app, Rect::new(0, 0, 80, 12))
            .iter()
            .map(rendered_line_text)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("+2 more aliases"), "{text}");
        assert!(text.contains("findings to view all"), "{text}");
    }

    fn rendered_line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }
}
