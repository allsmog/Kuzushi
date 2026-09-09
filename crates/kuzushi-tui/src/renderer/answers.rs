use super::*;
use crate::app::AnswerFocus;
use crate::ui_view_models::{
    answer_document, answer_scroll_start, answers_own_input, AnswerLineKind,
};
use ratatui::widgets::{Block, Borders};

pub(crate) fn render_answers(frame: &mut Frame<'_>, area: Rect, app: &ShellApp, compact: bool) {
    if compact {
        frame.render_widget(
            Paragraph::new("Answer available · Ctrl+T read / reply"),
            area,
        );
        return;
    }
    let block = Block::default()
        .title(answer_title(app))
        .borders(Borders::ALL)
        .border_style(theme::muted());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height < 3 {
        return;
    }
    let body = answer_body_area(area);
    let doc = answer_document(app, body.width as usize);
    render_answer_context(frame, inner, &doc);
    let start = answer_scroll_start(app, &doc, body.height as usize);
    let lines = doc
        .lines
        .iter()
        .skip(start)
        .take(body.height as usize)
        .map(|line| line.content.clone().style(answer_style(line.kind)))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), body);
    render_answer_position(frame, inner, start, body.height as usize, doc.lines.len());
}

fn answer_title(app: &ShellApp) -> &'static str {
    if app.router.answers().history != 0 {
        return " EARLIER CONTEXT ";
    }
    match app.agent_chat() {
        Some(chat) if chat.running => " ANSWERS · IN PROGRESS ",
        Some(chat) if !chat.partial_answer.is_empty() => " ANSWERS · INCOMPLETE ",
        _ => " ANSWERS ",
    }
}

pub(crate) fn answer_body_area(area: Rect) -> Rect {
    let inner = Block::default().borders(Borders::ALL).inner(area);
    Rect::new(
        inner.x,
        inner.y.saturating_add(2),
        inner.width,
        inner.height.saturating_sub(3),
    )
}

fn render_answer_context(
    frame: &mut Frame<'_>,
    inner: Rect,
    doc: &crate::ui_view_models::AnswerDocument,
) {
    let lines = [&doc.context_label, &doc.scope_label]
        .into_iter()
        .map(|text| muted(&fit(text, inner.width as usize)))
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines),
        Rect {
            height: 2.min(inner.height),
            ..inner
        },
    );
}

fn render_answer_position(
    frame: &mut Frame<'_>,
    inner: Rect,
    start: usize,
    visible: usize,
    total: usize,
) {
    let end = (start + visible).min(total);
    let text = format!(
        "{}–{end}/{total} · ↑/↓ PgUp/PgDn · Esc back",
        (start + 1).min(total)
    );
    let area = Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1);
    frame.render_widget(
        Paragraph::new(muted(&fit(&text, inner.width as usize))),
        area,
    );
}

fn answer_style(kind: AnswerLineKind) -> Style {
    match kind {
        AnswerLineKind::Context => theme::muted(),
        AnswerLineKind::Question => theme::heading(),
        AnswerLineKind::Answer => theme::primary(),
        AnswerLineKind::Error => theme::danger(),
    }
}

pub(crate) fn render_answer_prompt(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) -> bool {
    if !answers_own_input(app) {
        return false;
    }
    if app.router.answers().focus != AnswerFocus::Reply {
        let hint = answer_reading_hint(app);
        frame.render_widget(Paragraph::new(muted(hint)), area);
        return true;
    }
    let mut lines = vec![styled(
        "ASK › Enter sends · Shift+Enter newline · Esc keeps draft",
        theme::heading(),
    )];
    lines.extend(field_editor_lines(
        &app.router.answers().draft,
        area.width as usize,
        area.height.saturating_sub(1) as usize,
    ));
    frame.render_widget(Paragraph::new(lines), area);
    true
}

fn answer_reading_hint(app: &ShellApp) -> &'static str {
    if app.router.answers().draft.text().is_empty() {
        "Enter reply · Ctrl+T workspace"
    } else {
        "Enter resume · Ctrl+T workspace"
    }
}

pub(crate) fn answer_plain_lines(app: &ShellApp, width: usize) -> Vec<String> {
    if !crate::ui_view_models::answers_visible(app) {
        return Vec::new();
    }
    let mut lines = vec!["ANSWERS".to_string()];
    lines.extend(
        answer_document(app, width)
            .lines
            .iter()
            .map(|line| line.content.to_string()),
    );
    lines
}
