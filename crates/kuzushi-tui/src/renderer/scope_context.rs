use super::*;
use crate::ui_view_models::{scope_context, study_context::context_layout};
use ratatui::widgets::{Block, Borders};

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) -> bool {
    let Some(config) = app.scope_context_config() else {
        return false;
    };
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::subtle())
            .title(" SCOPE CONTEXT "),
        area,
    );
    super::study_config::render_study_target(frame, config, area);
    let rows = scope_context::rows(config);
    let layout = context_layout(area, rows.len());
    render_rows(frame, &rows, config.scope_context.cursor, layout.list);
    let (scroll, max) = render_detail(frame, config, layout.detail);
    render_controls(frame, layout.controls, scroll, max);
    true
}

fn render_detail(
    frame: &mut Frame<'_>,
    config: &crate::app::BatchScanConfig,
    area: Rect,
) -> (usize, usize) {
    let lines = scope_context::detail(config, area.width as usize);
    let max = lines.len().saturating_sub(area.height as usize);
    let scroll = config.scope_context.scroll.min(max);
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(scroll)
                .take(area.height as usize)
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        area,
    );
    (scroll, max)
}

fn render_controls(frame: &mut Frame<'_>, area: Rect, scroll: usize, max: usize) {
    let controls = vec![
        Line::styled(
            scope_context::reading_controls(area.width, scroll, max),
            theme::muted(),
        ),
        Line::styled(scope_context::controls(area.width)[1], theme::accent()),
    ];
    frame.render_widget(Paragraph::new(controls), area);
}

fn render_rows(frame: &mut Frame<'_>, rows: &[String], cursor: usize, area: Rect) {
    let start = cursor.saturating_sub((area.height as usize).saturating_sub(1));
    let lines = rows
        .iter()
        .enumerate()
        .skip(start)
        .take(area.height as usize)
        .map(|(index, row)| row_line(row, index == cursor, area.width as usize))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn row_line(row: &str, selected: bool, width: usize) -> Line<'static> {
    let (marker, style) = if selected {
        ("▸", theme::selection())
    } else {
        (" ", theme::primary())
    };
    Line::styled(fit(&format!("{marker} {row}"), width), style)
}
