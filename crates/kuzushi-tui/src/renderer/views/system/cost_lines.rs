use super::*;
use crate::ui_view_models::{cost_model, CostBudgetRow, CostModel, CostTone};

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
    for row in &model.spend_rows {
        lines.push(detail(&row.cells[0], &row.cells[1]));
    }
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
    let style = cost_tone_style(row.tone);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{:18}", row.cells[0]), theme::primary()),
        Span::styled(" [", theme::subtle()),
        Span::styled("█".repeat(row.fill), style),
        Span::styled("░".repeat(row.empty), theme::subtle()),
        Span::styled("] ", theme::subtle()),
        Span::styled(row.cells[1].clone(), theme::primary()),
        Span::styled(" / ", theme::muted()),
        Span::styled(row.cells[2].clone(), theme::muted()),
        Span::raw(" "),
        Span::styled(row.cells[3].clone(), style),
    ])
}

fn cost_tone_style(tone: CostTone) -> ratatui::style::Style {
    match tone {
        CostTone::Success => theme::success(),
        CostTone::Warn => theme::warn(),
        CostTone::Danger => theme::danger(),
    }
}
