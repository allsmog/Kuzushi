use super::*;
use ratatui::widgets::{Block, Borders, Clear};

pub(crate) fn reader_area(full: Rect) -> Rect {
    Rect::new(
        full.x + 1,
        full.y + 1,
        full.width.saturating_sub(2),
        full.height.saturating_sub(3),
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
    let lines = super::views::pinned_document_viewport_lines(
        logs_lines(app, area),
        area.height,
        app.router.logs().scroll(),
        logs_pinned_rows(app, area),
    );
    frame.render_widget(Paragraph::new(lines), area);
    frame.render_widget(
        Paragraph::new(reader_controls(area.width)).style(theme::muted()),
        Rect::new(area.x, full.bottom().saturating_sub(2), area.width, 1),
    );
    true
}

fn reader_controls(width: u16) -> &'static str {
    if width < 60 {
        return "PgUp/Dn · Esc back · Ctrl+G palette";
    }
    "↑↓ / PgUp/Dn · Home/End · Esc back · Ctrl+G palette"
}
