use super::*;

use crate::ui_view_models::{command_palette_model, CommandPaletteModel, PaletteRow};
use crate::{CommandPaletteFooter, CommandPaletteStatus};
use ratatui::layout::{Alignment, Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

pub(crate) fn command_palette_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    command_palette_model_lines(command_palette_model(app), area.width as usize)
}

fn command_palette_model_lines(model: CommandPaletteModel, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![
        palette_status_line(&model.status),
        raw("─".repeat(width)),
        blank(),
    ];
    lines.extend(
        model
            .rows
            .into_iter()
            .map(|row| palette_row_line(row, width)),
    );
    lines.push(blank());
    lines.push(raw("─".repeat(width)));
    lines.push(raw(palette_footer_stage_line(width, &model.footer)));
    lines.push(raw(palette_footer_keybind_line(&model.footer)));
    if let Some(prompt_module) = model.footer.prompt_module {
        lines.push(raw(format!(" kuzushi ({prompt_module})>")));
    } else {
        lines.push(raw(" kuzushi>"));
    }
    lines
}

fn palette_row_line(row: PaletteRow, width: usize) -> Line<'static> {
    match row {
        PaletteRow::Query(query) => Line::from(vec![
            Span::styled(" › ", theme::label()),
            Span::styled(fit(&query, width.saturating_sub(3)), theme::primary()),
        ]),
        PaletteRow::Summary(summary) => Line::styled(fit(&summary, width), theme::muted()),
        PaletteRow::Section(label) => divider(label, width.min(u16::MAX as usize) as u16),
        PaletteRow::Match {
            label,
            kind,
            description,
            selected,
        } => palette_match_line(label, kind, description, selected, width),
        PaletteRow::Empty(value) => {
            Line::styled(fit(&format!(" ∅ {value}"), width), theme::muted())
        }
        PaletteRow::Guidance(value) => Line::styled(fit(&value, width), theme::muted()),
        PaletteRow::Blank => blank(),
        PaletteRow::Legacy(value) => legacy_palette_line(value, width),
    }
}

fn palette_match_line(
    label: String,
    kind: &'static str,
    description: String,
    selected: bool,
    width: usize,
) -> Line<'static> {
    let marker = if selected { "▸" } else { " " };
    let kind_width = usize::from(width >= 32) * 7;
    let label_ceiling = width.saturating_sub(kind_width + 6);
    let label_width = (width * 3 / 10).clamp(8, 25).min(label_ceiling);
    let description_width = width.saturating_sub(label_width + kind_width + 6);
    let body = format!(
        "{marker} {} {} · {}",
        pad(&label, label_width),
        pad(kind, kind_width),
        fit(&description, description_width),
    );
    let style = if selected {
        theme::selection()
    } else {
        theme::primary()
    };
    Line::styled(pad(&fit(&body, width), width), style)
}

fn legacy_palette_line(value: String, width: usize) -> Line<'static> {
    if value.trim_start().starts_with('▸') {
        return Line::styled(pad(&fit(&value, width), width), theme::selection());
    }
    raw(fit(&value, width))
}

pub(crate) fn render_command_palette_overlay(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let model = command_palette_model(app);
    let body_area = overlay_body_area(area);
    if onboarding_overlay_origin(app) {
        frame.render_widget(Clear, area);
    } else {
        render_overlay_backdrop(frame, area);
    }
    if compact_command_palette(body_area) {
        render_compact_command_palette(frame, body_area, &model);
        return;
    }
    let row_count = model.rows.len();
    let modal = command_palette_rect(body_area, row_count);
    let row_width = modal.width.saturating_sub(2) as usize;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(" COMMAND PALETTE ", theme::heading()));
    let inner = block.inner(modal);
    let rows = palette_rows_for_capacity(model.rows, inner.height as usize)
        .into_iter()
        .map(|row| palette_row_line(row, row_width))
        .collect::<Vec<_>>();
    frame.render_widget(Clear, modal);
    frame.render_widget(block, modal);
    frame.render_widget(Paragraph::new(rows), inner);
}

fn onboarding_overlay_origin(app: &ShellApp) -> bool {
    matches!(
        app.router.overlay_origin(),
        Some(ShellView::TargetPicker | ShellView::PlanningPicker | ShellView::Setup)
    )
}

fn compact_command_palette(area: Rect) -> bool {
    area.height <= 5
}

fn render_compact_command_palette(frame: &mut Frame<'_>, area: Rect, model: &CommandPaletteModel) {
    if area.height == 0 {
        return;
    }
    frame.render_widget(
        Paragraph::new(compact_palette_rows(
            model,
            area.width as usize,
            area.height as usize,
        )),
        area,
    );
}

fn compact_palette_rows(
    model: &CommandPaletteModel,
    width: usize,
    height: usize,
) -> Vec<Line<'static>> {
    let mut rows = Vec::with_capacity(height);
    if height >= 4 {
        rows.push(Line::styled(
            fit(" COMMAND PALETTE", width),
            theme::heading(),
        ));
    }
    rows.push(compact_palette_query(&model.rows, width));
    rows.push(compact_palette_selection(&model.rows, width));
    rows.push(Line::styled(
        fit("↑/↓ move · Enter load · Esc close", width),
        theme::muted(),
    ));
    rows.truncate(height);
    rows
}

fn compact_palette_query(rows: &[PaletteRow], width: usize) -> Line<'static> {
    rows.iter()
        .find(|row| matches!(row, PaletteRow::Query(_)))
        .cloned()
        .map(|row| palette_row_line(row, width))
        .unwrap_or_else(|| Line::styled(fit(" › filter commands", width), theme::label()))
}

fn compact_palette_selection(rows: &[PaletteRow], width: usize) -> Line<'static> {
    rows.iter()
        .find(|row| {
            matches!(
                row,
                PaletteRow::Match { selected: true, .. } | PaletteRow::Empty(_)
            ) || matches!(row, PaletteRow::Legacy(value) if value.trim_start().starts_with('▸'))
        })
        .cloned()
        .map(|row| palette_row_line(row, width))
        .unwrap_or_else(|| Line::styled(fit(" ∅ no matching commands", width), theme::muted()))
}

fn palette_rows_for_capacity(rows: Vec<PaletteRow>, capacity: usize) -> Vec<PaletteRow> {
    if rows.len() <= capacity {
        return rows;
    }
    let guidance = rows
        .iter()
        .rev()
        .find(|row| matches!(row, PaletteRow::Guidance(_)))
        .cloned();
    let reserved = usize::from(guidance.is_some());
    let mut visible = rows
        .into_iter()
        .take(capacity.saturating_sub(reserved))
        .collect::<Vec<_>>();
    if let Some(guidance) = guidance {
        visible.push(guidance);
    }
    visible
}

fn command_palette_rect(area: Rect, row_count: usize) -> Rect {
    let width = area.width.saturating_sub(4).min(96);
    let requested_height = row_count.saturating_add(2).min(u16::MAX as usize) as u16;
    let height = requested_height.min(area.height.saturating_sub(2)).max(3);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(area.width.saturating_sub(width) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(area);
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(area.height.saturating_sub(height) / 3),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(horizontal[1]);
    vertical[1]
}

fn palette_status_line(status: &CommandPaletteStatus) -> Line<'static> {
    raw(format!(
        " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
        status.target, status.ctx, status.model, status.module, status.cost
    ))
}

fn palette_footer_stage_line(width: usize, footer: &CommandPaletteFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn palette_footer_keybind_line(footer: &CommandPaletteFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}

fn raw(value: impl Into<String>) -> Line<'static> {
    Line::raw(value.into())
}
