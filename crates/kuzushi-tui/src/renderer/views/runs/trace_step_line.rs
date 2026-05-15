use super::*;
use crate::ui_view_models::TraceStep;

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
    let aliases = sorted_finding_aliases(&app.findings);
    lines.push(blank());
    if aliases.is_empty() {
        lines.push(muted("aliases: load findings first with findings"));
        return lines;
    }
    lines.push(divider("ALIASES", area.width));
    for (alias, finding) in aliases.into_iter().take(3) {
        lines.push(detail(
            &alias,
            &format!("{} {}", short(&finding.fingerprint), finding.title),
        ));
    }
    lines
}
