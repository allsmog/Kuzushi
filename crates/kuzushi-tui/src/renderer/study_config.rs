use super::*;
use crate::app::{BatchScanConfig, BatchScanConfigRow};
use crate::ui_view_models::study_config::{
    study_allowance_summary, study_config_area, study_config_layout, study_controls_hint,
    study_detail_lines, study_projection, study_row_value,
};
use ratatui::widgets::{Block, Borders, Clear};

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
    if config.number_edit.is_some() {
        render_study_chrome(frame, &config, area);
        render_number_editor(frame, &config, area);
        return true;
    }
    render_study_surface(frame, app, &config, area);
    true
}

fn render_study_surface(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    config: &BatchScanConfig,
    area: Rect,
) {
    if app.study_engine_picker().is_some() && !app.notice_captures_escape() {
        super::study_engines::render_engine_picker(frame, app);
        return;
    }
    if app.context_generation().is_some() && !app.notice_captures_escape() {
        super::context_generation::render_context_generation(frame, app, area);
        return;
    }
    if app.study_context_picker().is_some() && !app.notice_captures_escape() {
        super::study_context::render_context_picker(frame, app, area);
        return;
    }
    render_study_chrome(frame, &config, area);
    render_config_body(frame, &config, area, app.notice_captures_escape());
}

fn render_study_chrome(frame: &mut Frame<'_>, config: &BatchScanConfig, area: Rect) {
    let title = if config.study.approved() {
        "APPROVED STUDY"
    } else {
        "PLAN A STUDY"
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(format!(" {title} "), theme::heading()))
        .title_bottom(
            Line::from(format!(
                " {} passes · {} worker(s) ",
                config.trials, config.effective_workers
            ))
            .right_aligned(),
        );
    frame.render_widget(block, area);
    render_study_target(frame, config, area);
    render_study_allowance(frame, config, area);
}

fn render_study_allowance(frame: &mut Frame<'_>, config: &BatchScanConfig, area: Rect) {
    frame.render_widget(
        Paragraph::new(Line::styled(
            study_allowance_summary(config, area.width.saturating_sub(4) as usize),
            theme::muted(),
        )),
        Rect::new(area.x + 2, area.y + 2, area.width.saturating_sub(4), 1),
    );
}

pub(super) fn render_study_target(frame: &mut Frame<'_>, config: &BatchScanConfig, area: Rect) {
    let target = config
        .target
        .file_name()
        .unwrap_or(config.target.as_os_str())
        .to_string_lossy();
    let target_line = Line::styled(
        fit(
            &format!("Repository: {target}"),
            area.width.saturating_sub(4) as usize,
        ),
        theme::muted(),
    );
    frame.render_widget(
        Paragraph::new(target_line),
        Rect::new(area.x + 2, area.y + 1, area.width.saturating_sub(4), 1),
    );
}

fn render_config_body(
    frame: &mut Frame<'_>,
    config: &BatchScanConfig,
    area: Rect,
    attention: bool,
) {
    let layout = study_config_layout(area);
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
    let offset = config.detail_scroll.min(maximum);
    let visible = lines
        .into_iter()
        .skip(offset)
        .take(layout.detail.height as usize)
        .map(|line| Line::styled(line, theme::primary()))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(visible), layout.detail);
    render_study_controls(
        frame,
        config.selected_row(),
        layout.controls,
        (offset, maximum),
        attention,
    );
}

fn render_study_controls(
    frame: &mut Frame<'_>,
    row: BatchScanConfigRow,
    area: Rect,
    position: (usize, usize),
    attention: bool,
) {
    let (offset, maximum) = position;
    let edit = study_controls_hint(row, area.width as usize, attention);
    let controls = vec![
        Line::styled(
            format!("↑↓ choose · PgUp/Dn {}/{}", offset + 1, maximum + 1),
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

fn render_number_editor(frame: &mut Frame<'_>, config: &BatchScanConfig, area: Rect) {
    let Some(edit) = config.number_edit.as_ref() else {
        return;
    };
    let body = Rect::new(
        area.x + 2,
        area.y + 2,
        area.width.saturating_sub(4),
        area.height.saturating_sub(5),
    );
    let Some((minimum, maximum)) = edit.bounds() else {
        return;
    };
    let mut lines = vec![Line::styled(
        format!("{} · {minimum}–{maximum}", edit.row.label()),
        theme::heading(),
    )];
    lines.extend(field_editor_lines(&edit.field, body.width as usize, 2));
    if let Some(error) = &edit.error {
        lines.extend(
            wrap_text(error, body.width as usize)
                .into_iter()
                .map(|line| Line::styled(line, theme::danger())),
        );
    }
    frame.render_widget(Paragraph::new(lines), body);
    let controls = Rect::new(body.x, area.bottom().saturating_sub(3), body.width, 2);
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("Enter save · Esc cancel", theme::accent()),
            Line::styled("Saving starts no work", theme::muted()),
        ]),
        controls,
    );
}

#[cfg(test)]
mod tests;
