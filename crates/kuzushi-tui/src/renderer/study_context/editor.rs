use super::*;
use crate::app::{ContextEditDraft, ContextEditMode};
use crate::renderer::shared::{field_editor_lines, text::wrap_text};
use crate::ui_view_models::context_edit::{
    context_choice_area, context_choice_detail_lines, context_choice_lines, context_draft_controls,
    context_edit_review_lines, context_edit_title, context_single_line_area,
};

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let Some(draft) = app.context_edit_draft() else {
        return;
    };
    let area = editor_area(draft, area, app.context_checkpoint_note().is_some());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(
            format!(" {} ", context_edit_title(draft.mode)),
            theme::heading(),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let footer = Rect::new(
        inner.x,
        inner.bottom().saturating_sub(2),
        inner.width,
        inner.height.min(2),
    );
    render_edit_notice(frame, draft, inner);
    if let Some(note) = app.context_checkpoint_note() {
        frame.render_widget(
            Paragraph::new(fit(&note, inner.width as usize)).style(theme::muted()),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
    }
    render_editor_body(
        frame,
        draft,
        content_area(inner, app.context_checkpoint_note().is_some()),
    );
    render_edit_controls(frame, draft, footer);
}

fn render_edit_notice(frame: &mut Frame<'_>, draft: &ContextEditDraft, area: Rect) {
    let notice = draft
        .notice
        .as_deref()
        .unwrap_or("Inactive copy · no model calls");
    frame.render_widget(
        Paragraph::new(fit(notice, area.width as usize)).style(theme::muted()),
        Rect::new(area.x, area.y, area.width, 1),
    );
}

fn render_edit_controls(frame: &mut Frame<'_>, draft: &ContextEditDraft, area: Rect) {
    frame.render_widget(
        Paragraph::new(
            context_draft_controls(draft)
                .into_iter()
                .map(|line| Line::styled(line, theme::accent()))
                .collect::<Vec<_>>(),
        ),
        area,
    );
}

fn render_editor_body(frame: &mut Frame<'_>, draft: &ContextEditDraft, area: Rect) {
    if draft.mode == ContextEditMode::Choosing {
        render_choices(frame, draft, area);
        return;
    }
    render_text_or_review(frame, draft, area);
}

fn render_text_or_review(frame: &mut Frame<'_>, draft: &ContextEditDraft, area: Rect) {
    if draft.mode == ContextEditMode::Recovery {
        let lines = crate::ui_view_models::context_edit::context_recovery_lines(
            draft,
            area.width as usize,
            area.height as usize,
        );
        frame.render_widget(
            Paragraph::new(lines.into_iter().map(Line::from).collect::<Vec<_>>()),
            area,
        );
        return;
    }
    if draft.mode == ContextEditMode::Writing {
        render_text_field(frame, draft, area);
        return;
    }
    if draft.mode == ContextEditMode::Fields {
        render_field_choices(frame, draft, area);
        return;
    }
    render_context_review(frame, draft, area);
}

fn render_choices(frame: &mut Frame<'_>, draft: &ContextEditDraft, area: Rect) {
    let lines = context_choice_lines(draft, area.width as usize, area.height as usize);
    frame.render_widget(
        Paragraph::new(lines.into_iter().map(Line::from).collect::<Vec<_>>()),
        area,
    );
}

fn content_area(inner: Rect, checkpoint: bool) -> Rect {
    let heading = 1 + u16::from(checkpoint);
    Rect::new(
        inner.x,
        inner.y.saturating_add(heading),
        inner.width,
        inner.height.saturating_sub(heading + 2),
    )
}

fn editor_area(draft: &ContextEditDraft, area: Rect, checkpoint: bool) -> Rect {
    if draft.mode == ContextEditMode::Choosing {
        return context_choice_area(draft, area, checkpoint);
    }
    if draft.mode == ContextEditMode::Writing
        && draft.entries[draft.cursor].constraint
            == kuzushi_core::capabilities::threat_model::ContextEditConstraint::SingleLine
    {
        return context_single_line_area(area, checkpoint);
    }
    area
}

fn choice_body_area(app: &ShellApp, draft: &ContextEditDraft) -> Rect {
    let viewport = app.viewport();
    let outer =
        crate::ui_view_models::study_config::study_config_area(viewport.columns, viewport.rows);
    let checkpoint = app.context_checkpoint_note().is_some();
    let area = editor_area(draft, outer, checkpoint);
    content_area(area.inner(ratatui::layout::Margin::new(1, 1)), checkpoint)
}

pub(crate) fn context_choice_page_rows(app: &ShellApp) -> usize {
    let Some(draft) = app.context_edit_draft() else {
        return 1;
    };
    choice_body_area(app, draft).height.saturating_sub(2).max(1) as usize
}

pub(crate) fn context_choice_offset_after_page(
    app: &ShellApp,
    code: crossterm::event::KeyCode,
) -> usize {
    use crossterm::event::KeyCode;
    let Some(draft) = app.context_edit_draft() else {
        return 0;
    };
    let body = choice_body_area(app, draft);
    let maximum = context_choice_detail_lines(draft, body.width as usize)
        .len()
        .saturating_sub(body.height as usize);
    let current = draft.scroll.min(maximum);
    let step = body.height.saturating_sub(1).max(1) as usize;
    [
        (KeyCode::PageUp, current.saturating_sub(step)),
        (KeyCode::PageDown, current.saturating_add(step).min(maximum)),
        (KeyCode::Home, 0),
        (KeyCode::End, maximum),
    ]
    .into_iter()
    .find_map(|(key, offset)| (key == code).then_some(offset))
    .unwrap_or(current)
}

fn render_text_field(frame: &mut Frame<'_>, draft: &ContextEditDraft, area: Rect) {
    let entry = &draft.entries[draft.cursor];
    frame.render_widget(
        Paragraph::new(fit(&entry.label, area.width as usize)).style(theme::heading()),
        Rect::new(area.x, area.y, area.width, 1),
    );
    let body = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    let Some(field) = &entry.editor else {
        return;
    };
    frame.render_widget(
        Paragraph::new(field_editor_lines(
            field,
            body.width as usize,
            body.height as usize,
        )),
        body,
    );
}

fn render_field_choices(frame: &mut Frame<'_>, draft: &ContextEditDraft, area: Rect) {
    let width = area.width as usize;
    let height = area.height as usize;
    let start = draft.cursor.saturating_sub(height.saturating_sub(1));
    let lines = draft
        .entries
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(index, entry)| {
            let marker = if index == draft.cursor { "▸" } else { " " };
            let changed = if entry.changed() { "* " } else { "" };
            Line::styled(
                fit(&format!("{marker} {changed}{}", entry.label), width),
                theme::primary(),
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_context_review(frame: &mut Frame<'_>, draft: &ContextEditDraft, area: Rect) {
    let lines = if draft.mode == ContextEditMode::Discard {
        vec!["Discard this draft's unsaved text? The original context stays unchanged.".into()]
    } else {
        context_edit_review_lines(draft, area.width as usize)
    };
    let lines = lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, area.width as usize))
        .collect::<Vec<_>>();
    let start = draft
        .scroll
        .min(lines.len().saturating_sub(area.height as usize));
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(start)
                .take(area.height as usize)
                .map(Line::from)
                .collect::<Vec<_>>(),
        ),
        area,
    );
}
