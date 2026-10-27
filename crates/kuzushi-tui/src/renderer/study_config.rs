use super::*;
use crate::app::{BatchScanConfig, BatchScanConfigRow};
use crate::ui_view_models::study_config::{
    study_config_area, study_controls_hint, study_detail_lines, study_projection, study_read_hint,
    study_reader_layout, study_row_value,
};
use ratatui::widgets::{Block, Borders, Clear};
mod case_name;
mod chrome;
mod matrix;
mod number_editor;
use chrome::render_study_chrome;
pub(super) use chrome::render_study_target;
use matrix::{render_context_matrix, render_context_results};
use number_editor::render_number_editor;

pub(super) fn render_study_config(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    if !app.batch_config_open() || app.advisory().pending_confirm.is_some() {
        return false;
    }
    let Some(config) = study_projection(app) else {
        return false;
    };
    let full = frame.area();
    let area = study_config_area(full.width, full.height);
    frame.render_widget(Clear, full);
    if let Some(lines) = crate::ui_view_models::study_config::recovery::lines(
        app,
        area.width.saturating_sub(4) as usize,
        area.height.saturating_sub(5) as usize,
    ) {
        render_recovery(frame, lines, &config, area);
        return true;
    }
    render_study_editors(frame, app, &config, area);
    true
}

fn render_study_editors(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    config: &BatchScanConfig,
    area: Rect,
) {
    if config.context_case_name_edit().is_some() {
        case_name::render(frame, &config, area, app.study_checkpoint_note());
        return;
    }
    if config.number_edit.is_some() {
        render_study_chrome(frame, &config, area);
        render_number_editor(frame, &config, area);
        return;
    }
    render_study_surface(frame, app, config, area);
}

fn render_recovery(
    frame: &mut Frame<'_>,
    lines: Vec<String>,
    config: &BatchScanConfig,
    area: Rect,
) {
    use crate::ui_view_models::study_config::recovery::{hint, title};
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", title(&config.draft_recovery)));
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);
    frame.render_widget(
        ratatui::widgets::Paragraph::new(lines.join("\n")),
        Rect::new(
            inner.x,
            inner.y,
            inner.width,
            inner.height.saturating_sub(2),
        ),
    );
    frame.render_widget(
        ratatui::widgets::Paragraph::new(hint(&config.draft_recovery))
            .wrap(ratatui::widgets::Wrap { trim: false }),
        Rect::new(inner.x, inner.bottom().saturating_sub(2), inner.width, 2),
    );
}

fn render_study_surface(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    config: &BatchScanConfig,
    area: Rect,
) {
    if app.review_study_is_open() {
        super::review_study::render_review_study(frame, app, area);
        return;
    }
    if config.context_result_cursor.is_some() {
        render_context_results(frame, app, area);
        return;
    }
    if !app.study_notice_captures_escape() && render_study_picker(frame, app, area) {
        return;
    }
    render_study_chrome(frame, &config, area);
    render_config_body(frame, &config, area, app.study_notice_captures_escape());
}

fn render_study_picker(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) -> bool {
    if let Some(config) = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .filter(|config| config.study.matrix.open)
    {
        render_context_matrix(frame, app, config, area);
        return true;
    }
    render_remaining_study_picker(frame, app, area)
}

fn render_remaining_study_picker(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) -> bool {
    if render_study_auxiliary_picker(frame, app, area) {
        return true;
    }
    if app.context_generation().is_some() {
        super::context_generation::render_context_generation(frame, app, area);
        return true;
    }
    if app.study_context_picker().is_some() {
        super::study_context::render_context_picker(frame, app, area);
        return true;
    }
    super::scope_context::render(frame, app, area)
}

fn render_study_auxiliary_picker(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) -> bool {
    super::study_brief::render(frame, app, area) || render_configuration_picker(frame, app)
}

fn render_config_body(
    frame: &mut Frame<'_>,
    config: &BatchScanConfig,
    area: Rect,
    attention: bool,
) {
    let layout = study_reader_layout(area, config.detail_reader_scroll.is_some());
    let count = layout.list.height as usize;
    let start = config.cursor.saturating_sub(count.saturating_sub(1));
    let rows = BatchScanConfigRow::ALL
        .iter()
        .enumerate()
        .skip(start)
        .take(count)
        .map(|(index, row)| config_row(config, index, *row, layout.list.width as usize))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(rows), layout.list);
    let lines = study_detail_lines(config, layout.detail.width as usize);
    let maximum = lines.len().saturating_sub(layout.detail.height as usize);
    let offset = config
        .detail_reader_scroll
        .unwrap_or(config.detail_scroll)
        .min(maximum);
    let visible = lines
        .into_iter()
        .skip(offset)
        .take(layout.detail.height as usize)
        .map(|line| Line::styled(line, theme::primary()))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(visible), layout.detail);
    render_study_controls(frame, config, layout.controls, (offset, maximum), attention);
}

fn render_study_controls(
    frame: &mut Frame<'_>,
    config: &BatchScanConfig,
    area: Rect,
    position: (usize, usize),
    attention: bool,
) {
    let (offset, maximum) = position;
    let edit = study_controls_hint(config.selected_row(), area.width as usize, attention);
    let controls = vec![
        Line::styled(
            study_read_hint(config, attention, offset, maximum),
            theme::muted(),
        ),
        Line::styled(edit, theme::accent()),
    ];
    frame.render_widget(Paragraph::new(controls), area);
}

fn config_row(
    config: &BatchScanConfig,
    index: usize,
    row: BatchScanConfigRow,
    width: usize,
) -> Line<'static> {
    let selected = index == config.cursor;
    let marker = if selected { "▸" } else { " " };
    let style = if selected {
        theme::selection()
    } else {
        theme::primary()
    };
    Line::styled(
        fit(
            &format!("{marker} {}  {}", row.label(), study_row_value(config, row)),
            width,
        ),
        style,
    )
}

#[cfg(test)]
mod tests;

fn render_configuration_picker(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    if app.study_resource_picker().is_some() {
        super::study_resources::render_resource_picker(frame, app);
        return true;
    }
    if app.study_engine_picker().is_some() {
        super::study_engines::render_engine_picker(frame, app);
        return true;
    }
    false
}
