use super::*;
use crate::app::{BatchScanConfig, BatchScanConfigRow};
use crate::ui_view_models::study_config::{
    study_allowance_summary, study_config_area, study_controls_hint, study_detail_lines,
    study_projection, study_read_hint, study_reader_layout, study_row_value, study_surface_title,
    study_workload_summary,
};
use ratatui::widgets::{Block, Borders, Clear};
mod case_name;

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

fn render_context_matrix(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    config: &BatchScanConfig,
    area: Rect,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" CONTEXT CASES ");
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);
    let lines = matrix_surface_lines(app, config, inner);
    frame.render_widget(
        ratatui::widgets::Paragraph::new(lines.join("\n")),
        Rect::new(
            inner.x,
            inner.y,
            inner.width,
            inner.height.saturating_sub(matrix_control_height(
                inner.width,
                config.study.matrix.results,
            )),
        ),
    );
    if config.study.matrix.results {
        render_matrix_result_controls(frame, inner);
    } else {
        render_matrix_controls(frame, inner)
    };
}

fn matrix_surface_lines(app: &ShellApp, config: &BatchScanConfig, inner: Rect) -> Vec<String> {
    if config.study.matrix.results {
        return crate::ui_view_models::matrix_result_lines(
            app,
            inner.width as usize,
            inner.height.saturating_sub(3) as usize,
        );
    }
    crate::ui_view_models::context_matrix_lines(
        config,
        inner.width as usize,
        inner
            .height
            .saturating_sub(matrix_control_height(inner.width, false)) as usize,
    )
}

fn render_matrix_result_controls(frame: &mut Frame<'_>, inner: Rect) {
    let hints = "↑↓ · Enter pass · b base · R report\nPgUp/PgDn detail · r refresh · Esc";
    frame.render_widget(
        ratatui::widgets::Paragraph::new(hints),
        Rect::new(inner.x, inner.bottom().saturating_sub(2), inner.width, 2),
    );
}

fn render_matrix_controls(frame: &mut Frame<'_>, inner: Rect) {
    let (hints, height) = if inner.width < 50 {
        (
            "↑↓ · Enter inspect · n rename\na add · b baseline · p passes\nx remove · c clear · v results\nL next · Esc back",
            4,
        )
    } else {
        (
            "↑↓ · Enter inspect · n rename · a add\nb baseline · p passes · x remove · c clear\nv results · L next · Esc back",
            3,
        )
    };
    frame.render_widget(
        ratatui::widgets::Paragraph::new(hints),
        Rect::new(
            inner.x,
            inner.bottom().saturating_sub(height),
            inner.width,
            height,
        ),
    );
}

fn matrix_control_height(width: u16, results: bool) -> u16 {
    if width < 50 && !results {
        4
    } else {
        3
    }
}

fn render_context_results(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" COMPARE CONTEXT EXPERIMENT ");
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);
    let lines = crate::ui_view_models::study_config::context_result_lines(
        app,
        inner.width as usize,
        inner.height.saturating_sub(2) as usize,
    );
    frame.render_widget(
        Paragraph::new(lines.into_iter().map(Line::from).collect::<Vec<_>>()),
        Rect {
            height: inner.height.saturating_sub(2),
            ..inner
        },
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("↑↓ pass · Enter compare · Esc back"),
            Line::from("r refresh · x clear · no work starts"),
        ]),
        Rect {
            y: inner.bottom().saturating_sub(2),
            height: 2,
            ..inner
        },
    );
}

fn render_study_chrome(frame: &mut Frame<'_>, config: &BatchScanConfig, area: Rect) {
    let title = study_surface_title(config);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(format!(" {title} "), theme::heading()))
        .title_bottom(Line::from(format!(" {} ", study_workload_summary(config))).right_aligned());
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
