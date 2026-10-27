use super::*;
use crate::ui_view_models::study_engines::{
    engine_apply_controls, engine_area, engine_detail, engine_layout, engine_line,
    engine_read_position, engine_rows, engine_window,
};
use ratatui::widgets::{Block, Borders, Scrollbar, ScrollbarOrientation, ScrollbarState};

pub(super) fn render_engine_picker(frame: &mut Frame<'_>, app: &ShellApp) {
    let Some(picker) = app.study_engine_picker() else {
        return;
    };
    let full = frame.area();
    let area = engine_area(full);
    render_engine_header(frame, app, area);
    let rows = engine_rows(app);
    let layout = engine_layout(full.width, full.height, rows.len());
    render_engine_list(frame, &rows, layout.list, picker.cursor);
    render_engine_detail(frame, app, layout.detail, picker.scroll);
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(
                format!(
                    "↑↓ Space PgUp/Dn r check {}",
                    engine_read_position(app, layout.detail)
                ),
                theme::muted(),
            ),
            Line::styled(engine_apply_controls(app), theme::accent()),
        ]),
        layout.controls,
    );
}

fn render_engine_header(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::subtle())
            .title(Span::styled(" CHOOSE DISCOVERY ENGINES ", theme::heading())),
        area,
    );
    if let Some(config) = app.router.campaign().batch_scan_config.as_ref() {
        super::study_config::render_study_target(frame, config, area);
    }
}

fn render_engine_list(
    frame: &mut Frame<'_>,
    rows: &[crate::ui_view_models::study_engines::StudyEngineRow],
    area: Rect,
    cursor: usize,
) {
    let window = engine_window(rows.len(), cursor, area.height as usize);
    let mut text_area = area;
    if rows.len() > area.height as usize {
        text_area.width = text_area.width.saturating_sub(1);
    }
    let visible = rows
        .iter()
        .enumerate()
        .skip(window.start)
        .take(window.len())
        .map(|(index, row)| {
            Line::styled(
                fit(&engine_line(row, index == cursor), text_area.width as usize),
                if index == cursor {
                    theme::selection()
                } else {
                    theme::primary()
                },
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(visible), text_area);
    render_engine_scrollbar(frame, area, rows.len(), window);
}

fn render_engine_scrollbar(
    frame: &mut Frame<'_>,
    area: Rect,
    count: usize,
    window: std::ops::Range<usize>,
) {
    if count <= area.height as usize {
        return;
    }
    let mut state = ScrollbarState::new(count.saturating_sub(window.len()).saturating_add(1))
        .position(window.start)
        .viewport_content_length(window.len());
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some(continuation_marker(window.start > 0, "↑")))
        .end_symbol(Some(continuation_marker(window.end < count, "↓")))
        .thumb_symbol("█")
        .track_symbol(Some("│"))
        .thumb_style(theme::accent())
        .track_style(theme::muted())
        .begin_style(theme::muted())
        .end_style(theme::muted());
    frame.render_stateful_widget(scrollbar, area, &mut state);
}

fn continuation_marker(more: bool, marker: &'static str) -> &'static str {
    more.then_some(marker).unwrap_or(" ")
}

fn render_engine_detail(frame: &mut Frame<'_>, app: &ShellApp, area: Rect, scroll: usize) {
    let lines = engine_detail(app, area.width as usize);
    let max = lines.len().saturating_sub(area.height as usize);
    let lines = lines
        .into_iter()
        .skip(scroll.min(max))
        .take(area.height as usize)
        .map(|line| Line::styled(line, theme::primary()))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}
