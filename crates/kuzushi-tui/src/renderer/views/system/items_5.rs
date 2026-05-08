use super::*;

pub(crate) fn cost_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    // BUDGETS section ----------------------------------------------------
    lines.push(divider("BUDGETS", area.width));
    let session = app.session_cost_usd;
    let session_budget = app.session_budget_usd.unwrap_or(5.0);
    lines.push(cost_budget_bar("this session    ", session, session_budget));
    if let Some(last) = app.last_tool_cost_usd {
        lines.push(cost_budget_bar("last tool       ", last, session_budget));
    }
    lines.push(blank());

    // SPEND section ------------------------------------------------------
    lines.push(divider("SPEND", area.width));
    let session_text = format_session_cost(session);
    let last_text = app
        .last_tool_cost_usd
        .map(|c| format!("${c:.4}"))
        .unwrap_or_else(|| "—".to_string());
    lines.push(detail("session", &session_text));
    lines.push(detail("last tool", &last_text));
    if let Some(budget) = app.session_budget_usd {
        lines.push(detail("budget", &format!("${budget:.2}")));
    } else {
        lines.push(detail("budget", "unset"));
    }
    lines.push(blank());

    // CTA row
    lines.push(command_list_line(
        &["model <provider:id>", "config", "back"],
        area.width as usize,
    ));
    lines.push(muted(
        "Per-tool spend ledger appears once Rust tools report `costUsd` (scanner-only work may stay $0).",
    ));
    lines
}

pub(crate) fn cost_budget_bar(label: &str, used: f64, cap: f64) -> Line<'static> {
    let bar_w: usize = 30;
    let pct = if cap > 0.0 {
        (used / cap).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let fill = (bar_w as f64 * pct).round() as usize;
    let empty = bar_w - fill;
    let pct_int = (pct * 100.0).round() as usize;
    let style = if pct_int >= 100 {
        theme::danger()
    } else if pct_int >= 85 {
        theme::warn()
    } else {
        theme::success()
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{:18}", label), theme::primary()),
        Span::styled(" [", theme::subtle()),
        Span::styled("█".repeat(fill), style),
        Span::styled("░".repeat(empty), theme::subtle()),
        Span::styled("] ", theme::subtle()),
        Span::styled(format!("${used:>6.2}"), theme::primary()),
        Span::styled(" / ", theme::muted()),
        Span::styled(format!("${cap:>6.2}"), theme::muted()),
        Span::raw(" "),
        Span::styled(format!("{pct_int:>3}%"), style),
    ])
}
