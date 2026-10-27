use super::*;

pub(super) fn render(frame: &mut Frame<'_>, area: Rect, state: &crate::app::ScopeCorrectionEditor) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" CORRECT SCOPE JSON ");
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);
    let body = render_header(frame, inner, state);
    frame.render_widget(
        Paragraph::new(crate::renderer::shared::field_editor_lines(
            &state.editor,
            body.width as usize,
            body.height as usize,
        )),
        body,
    );
    frame.render_widget(
        Paragraph::new(crate::ui_view_models::context_generation::CORRECTION_CONTROLS),
        Rect {
            y: inner.bottom().saturating_sub(2),
            height: 2,
            ..inner
        },
    );
}

fn render_header(
    frame: &mut Frame<'_>,
    inner: Rect,
    state: &crate::app::ScopeCorrectionEditor,
) -> Rect {
    let notice = crate::ui_view_models::context_generation::correction_notice(state);
    let header = crate::renderer::shared::text::wrap_text(notice, inner.width as usize);
    let header_rows = header
        .len()
        .min(usize::from(inner.height.saturating_sub(4)))
        .min(4) as u16;
    frame.render_widget(
        Paragraph::new(
            header
                .into_iter()
                .take(header_rows as usize)
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        Rect {
            height: header_rows,
            ..inner
        },
    );
    Rect {
        y: inner.y + header_rows,
        height: inner.height.saturating_sub(header_rows + 2),
        ..inner
    }
}
