use super::*;
use crate::app::{ContextEditDraft, ContextEditMode};
use crate::renderer::shared::{field_editor_lines, text::wrap_text};
use crate::ui_view_models::context_edit::{
    context_draft_controls, context_edit_review_lines, context_edit_title,
};

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let Some(draft) = app.context_edit_draft() else {
        return;
    };
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
    let mut body = Rect::new(
        inner.x,
        inner.y,
        inner.width,
        inner.height.saturating_sub(footer.height),
    );
    render_edit_notice(frame, draft, body);
    body.y += 1;
    body.height = body.height.saturating_sub(1);
    if let Some(note) = app.context_checkpoint_note() {
        frame.render_widget(
            Paragraph::new(fit(&note, body.width as usize)).style(theme::muted()),
            Rect::new(body.x, body.y, body.width, 1),
        );
        body.y += 1;
        body.height = body.height.saturating_sub(1);
    }
    render_editor_body(frame, draft, body);
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
