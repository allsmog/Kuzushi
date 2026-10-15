use super::*;
use crate::app::{BriefEditor, BriefMode};
use crate::ui_view_models::study_config::brief;
use ratatui::widgets::{Block, Borders};

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) -> bool {
    let Some(editor) = app.brief_editor() else {
        return false;
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(brief::title(editor.mode));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let checkpoint = app.study_checkpoint_note();
    let notices = brief::notice_lines(editor, checkpoint.as_deref());
    let height = (notices.len() as u16).min(2).min(inner.height);
    let (body, footer) = body_and_footer(inner, height);
    let lines = notices
        .into_iter()
        .map(|line| fit(&line, inner.width as usize))
        .collect::<Vec<_>>()
        .join("\n");
    frame.render_widget(
        Paragraph::new(lines).style(theme::muted()),
        Rect::new(inner.x, inner.y, inner.width, height),
    );
    render_body(frame, editor, body);
    let controls = super::shared::text::wrap_text(
        brief::controls(editor.mode, inner.width < 44),
        inner.width as usize,
    );
    let controls = reading_controls(editor, body, controls);
    frame.render_widget(
        Paragraph::new(controls.join("\n")).style(theme::muted()),
        footer,
    );
    true
}

fn reading_controls(editor: &BriefEditor, body: Rect, mut controls: Vec<String>) -> Vec<String> {
    if editor.mode == BriefMode::Writing {
        return controls;
    }
    let count = brief::reading_lines(editor, body.width as usize).len();
    let first = editor
        .scroll
        .min(count.saturating_sub(body.height as usize));
    controls.push(format!(
        "PgUp/Dn · rows {}-{}/{}",
        first + 1,
        (first + body.height as usize).min(count),
        count
    ));
    controls
}

fn body_and_footer(inner: Rect, notice_height: u16) -> (Rect, Rect) {
    let footer_height = inner.height.min(2);
    let footer = Rect::new(
        inner.x,
        inner.bottom().saturating_sub(footer_height),
        inner.width,
        footer_height,
    );
    let body = Rect::new(
        inner.x,
        inner.y.saturating_add(notice_height),
        inner.width,
        inner.height.saturating_sub(footer_height + notice_height),
    );
    (body, footer)
}

fn render_body(frame: &mut Frame<'_>, editor: &BriefEditor, area: Rect) {
    if editor.mode == BriefMode::Writing {
        let lines = super::shared::field_editor_lines(
            &editor.editor,
            area.width as usize,
            area.height as usize,
        );
        frame.render_widget(Paragraph::new(lines), area);
        return;
    }
    let lines = brief::reading_lines(editor, area.width as usize);
    let offset = editor
        .scroll
        .min(lines.len().saturating_sub(area.height as usize));
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(offset)
                .take(area.height as usize)
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        area,
    );
}
