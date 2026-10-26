use super::*;

pub(super) fn render_number_editor(frame: &mut Frame<'_>, config: &BatchScanConfig, area: Rect) {
    let Some(edit) = config.number_edit.as_ref() else {
        return;
    };
    let body = Rect::new(
        area.x + 2,
        area.y + 3,
        area.width.saturating_sub(4),
        area.height.saturating_sub(6),
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
