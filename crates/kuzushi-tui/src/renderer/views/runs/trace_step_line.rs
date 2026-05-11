use super::*;

pub(crate) fn trace_step_line(step: &TraceStep, width: u16) -> Line<'static> {
    let kind_style = match step.severity.as_deref() {
        Some("danger") => theme::danger(),
        Some("warn") => theme::warn(),
        _ => match step.kind.as_str() {
            "plan" => theme::label(),
            "tool" | "tool-start" => theme::success(),
            "done" | "tool-complete" => theme::success(),
            "llm" | "reasoning" | "tool-progress" => theme::accent(),
            "refused" | "failing" => theme::danger(),
            "critic" => theme::warn(),
            _ => theme::muted(),
        },
    };
    let latency = step
        .latency_ms
        .map(|ms| {
            if ms >= 1000 {
                format!("{:.1}s", ms as f64 / 1000.0)
            } else {
                format!("{ms}ms")
            }
        })
        .unwrap_or_else(|| "—".to_string());
    let cost = step
        .cost_usd
        .map(|c| format!("${c:.4}"))
        .unwrap_or_else(|| "—".to_string());
    let label = trace_step_label(step);
    let label_budget = (width as usize).saturating_sub(28).max(20);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{:>3} ", step.n), theme::subtle()),
        Span::styled(format!("{:8}", step.kind), kind_style),
        Span::raw(" "),
        Span::styled(fit(&label, label_budget), theme::primary()),
        Span::raw("  "),
        Span::styled(format!("{:>7}", latency), theme::muted()),
        Span::raw("  "),
        Span::styled(cost, theme::muted()),
    ])
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

pub(crate) fn run_artifact_path(app: &ShellApp, run_id: &str, leaf: &str) -> std::path::PathBuf {
    let runs_root = app
        .target
        .as_deref()
        .map(|target| target.join(".kuzushi/runs"))
        .unwrap_or_else(|| std::path::PathBuf::from(".kuzushi/runs"));
    runs_root.join(run_id).join(leaf)
}

pub(crate) fn run_artifact_detail(label: &str, path: &std::path::Path) -> Line<'static> {
    let display = path.display().to_string();
    let suffix = if path.exists() { "" } else { " (missing)" };
    detail(label, &format!("{display}{suffix}"))
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
