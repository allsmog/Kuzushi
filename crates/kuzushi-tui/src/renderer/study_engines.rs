use super::*;
use crate::ui_view_models::study_engines::{
    engine_apply_controls, engine_area, engine_detail, engine_layout, engine_line,
    engine_read_position, engine_rows,
};
use ratatui::widgets::{Block, Borders};

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
    let start = cursor.saturating_sub((area.height as usize).saturating_sub(1));
    let visible = rows
        .iter()
        .enumerate()
        .skip(start)
        .take(area.height as usize)
        .map(|(index, row)| {
            Line::styled(
                fit(&engine_line(row, index == cursor), area.width as usize),
                if index == cursor {
                    theme::selection()
                } else {
                    theme::primary()
                },
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(visible), area);
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
