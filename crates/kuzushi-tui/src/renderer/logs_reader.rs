use super::*;
use ratatui::widgets::{Block, Borders, Clear};

pub(crate) fn reader_area(full: Rect) -> Rect {
    Rect::new(
        full.x + 1,
        full.y + 1,
        full.width.saturating_sub(2),
        full.height.saturating_sub(2 + footer_rows(full.width)),
    )
}

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    if app.shell_view() != ShellView::Logs
        || !app.router.logs().reader_open()
        || app.advisory().pending_confirm.is_some()
    {
        return false;
    }
    let full = frame.area();
    frame.render_widget(Clear, full);
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .title(" READ TRANSCRIPT ")
            .border_style(theme::subtle()),
        full,
    );
    let area = reader_area(full);
    let footer_height = footer_rows(full.width).min(full.height.saturating_sub(2));
    let lines = super::views::pinned_document_viewport_lines(
        logs_lines(app, area),
        area.height,
        app.router.logs().scroll(),
        logs_pinned_rows(app, area),
    );
    frame.render_widget(Paragraph::new(lines), area);
    frame.render_widget(
        Paragraph::new(reader_controls(
            area.width,
            app.router.logs().command_text_expanded(),
        ))
        .style(theme::muted()),
        Rect::new(
            area.x,
            full.bottom().saturating_sub(footer_height + 1),
            area.width,
            footer_height,
        ),
    );
    true
}

fn footer_rows(width: u16) -> u16 {
    if width < 82 {
        2
    } else {
        1
    }
}

fn reader_controls(width: u16, expanded: bool) -> &'static str {
    match (width < 80, expanded) {
        (true, false) => "c read commands · PgUp/Dn · Esc back\n↑↓ · Home/End · Ctrl+G palette",
        (true, true) => "c fold commands · PgUp/Dn · Esc back\n↑↓ · Home/End · Ctrl+G palette",
        (false, false) => "c read commands · ↑↓ / PgUp/Dn · Home/End · Esc back · Ctrl+G palette",
        (false, true) => "c fold commands · ↑↓ / PgUp/Dn · Home/End · Esc back · Ctrl+G palette",
    }
}
