use super::*;
use crate::ui_view_models::{health_model, HealthModel, HealthRow, HealthTone};

pub(crate) fn health_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let model = health_model(app);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("HEALTH", area.width));
    lines.push(muted(&fit(&model.summary, area.width as usize)));
    lines.push(blank());
    push_health_rows(&mut lines, &model, area.width as usize);
    push_health_commands(&mut lines, &model, area.width as usize);
    lines
}

fn push_health_rows(lines: &mut Vec<Line<'static>>, model: &HealthModel, width: usize) {
    for row in &model.rows {
        lines.push(health_row_line(row, width));
        if !row.next.is_empty() {
            lines.push(muted(&fit(&format!("       next: {}", row.next), width)));
        }
    }
}

fn health_row_line(row: &HealthRow, width: usize) -> Line<'static> {
    let detail_width = width.saturating_sub(25);
    Line::from(vec![
        Span::styled(format!("{:<5} ", row.status), health_tone_style(row.tone)),
        Span::styled(format!("{:<16}", row.check), theme::primary()),
        Span::styled(fit(&row.detail, detail_width), theme::muted()),
    ])
}

fn push_health_commands(lines: &mut Vec<Line<'static>>, model: &HealthModel, width: usize) {
    lines.push(blank());
    lines.push(command_list_line(&model.commands, width));
}

fn health_tone_style(tone: HealthTone) -> ratatui::style::Style {
    match tone {
        HealthTone::Pass => theme::success(),
        HealthTone::Warn => theme::warn(),
        HealthTone::Fail => theme::danger(),
    }
}
