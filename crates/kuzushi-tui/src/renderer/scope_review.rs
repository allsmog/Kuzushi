use super::*;
use crate::app::ScopeReviewState;
use crate::ui_view_models::{
    scope_review::*,
    study_config::{study_config_area, study_config_layout},
};
use ratatui::widgets::{Block, Borders, Clear};

pub(super) fn render_scope_review(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    if !app.scope_review_is_visible() {
        return false;
    }
    let Some(state) = app.scope_review() else {
        return false;
    };
    if app.advisory().pending_confirm.is_some() {
        return false;
    }
    let full = frame.area();
    let area = study_config_area(full.width, full.height);
    frame.render_widget(Clear, full);
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::subtle())
            .title(scope_title_line(app, state, area.width)),
        area,
    );
    render_scope_target(frame, state, area);
    render_scope_source(frame, app, state, area);
    if state.form.is_some() {
        render_scope_form(frame, state, area);
    } else {
        render_scope_panels(frame, app, state, area);
    }
    let controls = scope_controls(state).map(|text| Line::styled(text, theme::accent()));
    frame.render_widget(
        Paragraph::new(controls.to_vec()),
        study_config_layout(area).controls,
    );
    true
}

fn render_scope_target(frame: &mut Frame<'_>, state: &ScopeReviewState, area: Rect) {
    let target = state
        .target
        .file_name()
        .unwrap_or(state.target.as_os_str())
        .to_string_lossy();
    frame.render_widget(
        Paragraph::new(Line::styled(
            fit(
                &format!("Repository: {target}"),
                area.width.saturating_sub(4) as usize,
            ),
            theme::muted(),
        )),
        Rect::new(area.x + 2, area.y + 1, area.width.saturating_sub(4), 1),
    );
}

fn render_scope_source(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    state: &ScopeReviewState,
    area: Rect,
) {
    frame.render_widget(
        Paragraph::new(Line::styled(
            fit(
                scope_source_view(app, state).label(),
                area.width.saturating_sub(4) as usize,
            ),
            theme::muted(),
        )),
        Rect::new(area.x + 2, area.y + 2, area.width.saturating_sub(4), 1),
    );
}

fn scope_title_line(app: &ShellApp, state: &ScopeReviewState, width: u16) -> Line<'static> {
    let Some(field) = state.menu_search.as_ref().filter(|_| state.menu.is_some()) else {
        return Line::styled(
            format!(" {} ", scope_title(state, &scope_source_view(app, state))),
            theme::heading(),
        );
    };
    let mut line = Line::styled(" Search: ", theme::label());
    for content in field_editor_lines(field, width.saturating_sub(12) as usize, 1) {
        line.spans.extend(content.spans);
    }
    line
}

fn render_scope_panels(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    state: &ScopeReviewState,
    area: Rect,
) {
    let (rows, cursor) = scope_rows(state);
    let layout = scope_layout(area, rows.len());
    let start = cursor.saturating_sub(layout.list.height.saturating_sub(1) as usize);
    let lines = rows
        .into_iter()
        .enumerate()
        .skip(start)
        .take(layout.list.height as usize)
        .map(|(index, text)| {
            Line::styled(
                crate::renderer::shared::text::fit_scope_row(
                    &format!("{} {text}", if index == cursor { "▸" } else { " " }),
                    layout.list.width as usize,
                ),
                if index == cursor {
                    theme::selection()
                } else {
                    theme::primary()
                },
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), layout.list);
    let detail = scope_detail_lines(
        app,
        state,
        &scope_source_view(app, state),
        layout.detail.width as usize,
    );
    render_scope_document(frame, detail, state.scroll, layout.detail);
}

fn render_scope_document(frame: &mut Frame<'_>, lines: Vec<String>, scroll: usize, area: Rect) {
    let offset = scroll.min(lines.len().saturating_sub(area.height as usize));
    let visible = lines
        .into_iter()
        .skip(offset)
        .take(area.height as usize)
        .map(|line| Line::styled(line, theme::primary()))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(visible), area);
}

fn render_scope_form(frame: &mut Frame<'_>, state: &ScopeReviewState, area: Rect) {
    // Callers open this only with a form; a missing one draws nothing
    // rather than panicking inside raw-mode rendering.
    let Some(form) = state.form.as_ref() else {
        return;
    };
    let body = Rect::new(
        area.x + 2,
        area.y + 2,
        area.width.saturating_sub(4),
        area.height.saturating_sub(5),
    );
    let Some((label, field)) = form.fields.get(form.cursor) else {
        return;
    };
    let mut lines = vec![Line::styled(
        fit(
            &format!("Field {}/{}: {label}", form.cursor + 1, form.fields.len()),
            body.width as usize,
        ),
        theme::heading(),
    )];
    if let Some(notice) = &state.notice {
        lines.extend(
            wrap_text(notice, body.width as usize)
                .into_iter()
                .take(2)
                .map(|text| Line::styled(text, theme::muted())),
        );
    }
    lines.extend(field_editor_lines(
        field,
        body.width as usize,
        body.height.saturating_sub(lines.len() as u16) as usize,
    ));
    frame.render_widget(Paragraph::new(lines), body);
}

pub(super) fn scope_review_plain_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    if !app.scope_review_is_visible() {
        return None;
    }
    let state = app.scope_review()?;
    let mut text = vec![
        scope_title(state, &scope_source_view(app, state)),
        format!("Repository: {}", state.target.display()),
        scope_source_view(app, state).label().into(),
    ];
    text.extend(scope_search_label(state));
    text.extend(scope_rows(state).0);
    text.extend(scope_detail_lines(
        app,
        state,
        &scope_source_view(app, state),
        width,
    ));
    if let Some(form) = &state.form {
        text.extend(
            form.fields
                .iter()
                .map(|(label, field)| format!("{label}: {}", field.text())),
        );
    }
    text.extend(scope_controls(state).map(str::to_string));
    Some(
        text.into_iter()
            .flat_map(|line| wrap_text(&line, width))
            .collect(),
    )
}
