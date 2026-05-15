use super::*;
use crate::ui_view_models::{cost_model, CostBudgetRow, CostModel};

pub(crate) fn cost_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = cost_model(app);
    lines.push(blank());

    push_cost_budget_section(&mut lines, &model, area);
    push_cost_spend_section(&mut lines, &model, area);
    push_cost_commands(&mut lines, area);
    lines
}

fn push_cost_budget_section(lines: &mut Vec<Line<'static>>, model: &CostModel, area: Rect) {
    lines.push(divider("BUDGETS", area.width));
    for row in &model.budget_rows {
        lines.push(cost_budget_bar(row));
    }
    lines.push(blank());
}

fn push_cost_spend_section(lines: &mut Vec<Line<'static>>, model: &CostModel, area: Rect) {
    lines.push(divider("SPEND", area.width));
    lines.push(detail("session", &model.session_text));
    lines.push(detail("last tool", &model.last_tool_text));
    lines.push(detail("budget", &model.budget_text));
    lines.push(blank());
}

fn push_cost_commands(lines: &mut Vec<Line<'static>>, area: Rect) {
    lines.push(command_list_line(
        &["model <provider:id>", "config", "back"],
        area.width as usize,
    ));
    lines.push(muted(
        "Per-tool spend ledger appears once Rust tools report `costUsd` (scanner-only work may stay $0).",
    ));
}

pub(crate) fn cost_budget_bar(row: &CostBudgetRow) -> Line<'static> {
    let bar_w: usize = 30;
    let pct = row.percent as f64 / 100.0;
    let fill = ((bar_w as f64 * pct).round() as usize).min(bar_w);
    let empty = bar_w.saturating_sub(fill);
    let style = if row.percent >= 100 {
        theme::danger()
    } else if row.percent >= 85 {
        theme::warn()
    } else {
        theme::success()
    };
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{:18}", row.label), theme::primary()),
        Span::styled(" [", theme::subtle()),
        Span::styled("█".repeat(fill), style),
        Span::styled("░".repeat(empty), theme::subtle()),
        Span::styled("] ", theme::subtle()),
        Span::styled(format!("${:>6.2}", row.used), theme::primary()),
        Span::styled(" / ", theme::muted()),
        Span::styled(format!("${:>6.2}", row.cap), theme::muted()),
        Span::raw(" "),
        Span::styled(format!("{:>3}%", row.percent), style),
    ])
}
