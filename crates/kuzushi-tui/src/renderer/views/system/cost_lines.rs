use super::*;
use crate::ui_view_models::{cost_model, CostBudgetRow, CostModel, CostTone};

pub(crate) fn cost_page_rows(app: &ShellApp) -> Option<usize> {
    cost_reader_area(app).map(|area| usize::from(area.height).max(1))
}

pub(crate) fn cost_max_scroll(app: &ShellApp) -> Option<u16> {
    let area = cost_reader_area(app)?;
    let total = cost_lines(app, area).len();
    Some(
        total
            .saturating_sub(usize::from(area.height))
            .min(u16::MAX as usize) as u16,
    )
}

fn cost_reader_area(app: &ShellApp) -> Option<Rect> {
    if app.shell_view() != ShellView::Cost {
        return None;
    }
    let viewport = app.viewport();
    let primary =
        crate::renderer::primary_body_area(app, Rect::new(0, 0, viewport.columns, viewport.rows));
    Some(crate::ui_view_models::answers_layout(app, primary).workspace)
}

pub(crate) fn cost_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    if let Some(snapshot) = app.cost_screen_snapshot() {
        return cost_snapshot_lines(snapshot.clone(), area.width as usize);
    }

    let mut lines = context_strip(app, area);
    let model = cost_model(app);
    lines.push(blank());

    push_cost_budget_section(&mut lines, &model, area);
    push_cost_spend_section(&mut lines, &model, area);
    push_cost_commands(&mut lines, area);
    lines
}

fn cost_snapshot_lines(snapshot: CostScreenSnapshot, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        raw(format!(
            " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
            snapshot.status.target,
            snapshot.status.ctx,
            snapshot.status.model,
            snapshot.status.module,
            snapshot.status.cost
        )),
        raw("─".repeat(width)),
        blank(),
    ];
    lines.extend(snapshot.body_rows.into_iter().map(raw));
    lines.push(blank());
    lines.push(raw("─".repeat(width)));
    lines.push(raw(cost_footer_stage_line(width, &snapshot.footer)));
    lines.push(raw(cost_footer_keybind_line(&snapshot.footer)));
    lines.push(raw(cost_prompt_line(&snapshot.footer)));
    lines
}

fn cost_footer_stage_line(width: usize, footer: &CostScreenFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(display_width(&left) + display_width(&right))
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn cost_footer_keybind_line(footer: &CostScreenFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}

fn cost_prompt_line(footer: &CostScreenFooter) -> String {
    match footer.prompt_module.as_deref() {
        Some(module) => format!(" kuzushi ({module})>"),
        None => " kuzushi>".to_string(),
    }
}

fn push_cost_budget_section(lines: &mut Vec<Line<'static>>, model: &CostModel, area: Rect) {
    lines.push(divider("BUDGETS", area.width));
    if model.budget_rows.is_empty() {
        lines.push(detail("this session", "not enforced"));
    } else {
        for row in &model.budget_rows {
            if area.width < 100 || row.fill.is_none() {
                lines.extend(detail_wrapped(
                    &row.cells[0],
                    &format!(
                        "{} / stop {} · {}",
                        row.cells[1], row.cells[2], row.cells[3]
                    ),
                    area.width,
                ));
            } else {
                lines.push(cost_budget_bar(row));
            }
        }
    }
    lines.extend(
        [
            "Dollar stops use returned receipts.",
            "A request can overspend before its receipt arrives.",
            "Approved call limits apply separately.",
        ]
        .into_iter()
        .flat_map(|text| wrap_text(text, area.width as usize))
        .map(|line| muted(&line)),
    );
    lines.push(blank());
}

fn push_cost_spend_section(lines: &mut Vec<Line<'static>>, model: &CostModel, area: Rect) {
    lines.push(divider("SPEND", area.width));
    for row in &model.spend_rows {
        lines.extend(detail_wrapped(&row.cells[0], &row.cells[1], area.width));
    }
    lines.push(blank());
}

fn push_cost_commands(lines: &mut Vec<Line<'static>>, area: Rect) {
    lines.extend(command_list_lines(
        &["report", "replay <run-id>", "config", "back"],
        area.width as usize,
    ));
    lines.extend(
        wrap_text(
            "Saved run costs appear in report and replay. Missing cost telemetry stays unknown.",
            area.width as usize,
        )
        .into_iter()
        .map(|line| muted(&line)),
    );
}

fn raw(value: impl Into<String>) -> Line<'static> {
    Line::raw(value.into())
}

pub(crate) fn cost_budget_bar(row: &CostBudgetRow) -> Line<'static> {
    let style = cost_tone_style(row.tone);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(format!("{:18}", row.cells[0]), theme::primary()),
        Span::styled(" [", theme::subtle()),
        Span::styled("█".repeat(row.fill.unwrap_or(0)), style),
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

#[cfg(test)]
mod tests;
