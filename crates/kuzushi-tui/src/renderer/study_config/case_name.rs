use crate::app::BatchScanConfig;
use crate::renderer::shared::{field_editor_lines, text::wrap_text};
use crate::theme;
use ratatui::{
    layout::Rect,
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub(super) fn render(
    frame: &mut Frame<'_>,
    config: &BatchScanConfig,
    area: Rect,
    checkpoint: Option<String>,
) {
    let Some(edit) = config.context_case_name_edit() else {
        return;
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" NAME CONTEXT CASE ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let note = checkpoint
        .filter(|_| edit.error.is_none())
        .unwrap_or_else(|| crate::ui_view_models::case_name_notice(config).into());
    let notice = wrap_text(&note, inner.width as usize);
    let notice_height = notice.len().min(3) as u16;
    render_field(frame, &edit.field, inner, notice_height);
    render_controls(frame, inner, notice, notice_height);
}

fn render_field(
    frame: &mut Frame<'_>,
    field: &crate::app::FieldEditor,
    inner: Rect,
    notice_height: u16,
) {
    let body = Rect::new(
        inner.x + 1,
        inner.y + 2,
        inner.width.saturating_sub(2),
        inner.height.saturating_sub(3 + notice_height),
    );
    frame.render_widget(
        Paragraph::new("Name for this draft case").style(theme::heading()),
        Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), 1),
    );
    frame.render_widget(
        Paragraph::new(field_editor_lines(
            field,
            body.width as usize,
            body.height as usize,
        )),
        body,
    );
}

fn render_controls(frame: &mut Frame<'_>, inner: Rect, notice: Vec<String>, notice_height: u16) {
    frame.render_widget(
        Paragraph::new(
            notice
                .into_iter()
                .take(notice_height as usize)
                .map(ratatui::text::Line::from)
                .collect::<Vec<_>>(),
        )
        .style(theme::muted()),
        Rect::new(
            inner.x,
            inner.bottom().saturating_sub(1 + notice_height),
            inner.width,
            notice_height,
        ),
    );
    frame.render_widget(
        Paragraph::new("Enter save · Esc back (keeps draft)").style(theme::accent()),
        Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1),
    );
}
