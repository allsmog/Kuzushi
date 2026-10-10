//! Short campaign navigation gives finite work and recovery the full frame.
use super::*;
use ratatui::widgets::Clear;

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    let full = frame.area();
    if !super::views::compact_campaign_reader(app, full) {
        return false;
    }
    frame.render_widget(Clear, full);
    let lines = super::views::campaign_view_lines(app, full);
    frame.render_widget(Paragraph::new(lines), full);
    true
}
