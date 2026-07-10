use super::*;
use ratatui::style::{Color, Modifier};
use ratatui::widgets::{Block, Borders};

/// Atlas-native pane chrome: one stable vertical rail per pane, no nested box.
/// Focus changes color and title weight without changing the content geometry.
pub(crate) fn cockpit_pane_block(title: impl Into<Line<'static>>, focused: bool) -> Block<'static> {
    Block::default()
        .borders(Borders::LEFT)
        .border_style(cockpit_rail_style(focused))
        .title(title)
}

pub(crate) fn cockpit_title_style(focused: bool) -> Style {
    if focused {
        return theme::accent().add_modifier(Modifier::BOLD);
    }
    theme::muted()
}

fn cockpit_rail_style(focused: bool) -> Style {
    if focused {
        theme::accent()
    } else {
        theme::subtle()
    }
}

/// Full-width Atlas selection row. The `▸` marker keeps selection visible in
/// ANSI and no-color modes where background contrast may be unavailable.
pub(crate) fn selection_band(body: &str, selected: bool, width: usize) -> Line<'static> {
    let marker = if selected { "▸" } else { " " };
    let text = pad(&fit(&format!(" {marker} {body}"), width), width);
    if selected {
        return Line::styled(text, theme::selection());
    }
    Line::styled(text, theme::primary())
}

/// Remove competing accents from the preserved origin while an Atlas modal
/// owns focus. Symbols stay visible, but selection backgrounds and bold state
/// are replaced by one quiet backdrop style.
pub(crate) fn render_overlay_backdrop(frame: &mut Frame<'_>, area: Rect) {
    let style = theme::muted()
        .bg(Color::Reset)
        .remove_modifier(Modifier::BOLD | Modifier::REVERSED);
    frame.buffer_mut().set_style(area, style);
}
