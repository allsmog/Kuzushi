use super::*;
use ratatui::style::{Color, Modifier};
use ratatui::widgets::{Block, Borders, Clear};

/// Atlas-native pane chrome: one stable vertical rail per pane, no nested box.
/// Focus changes color and title weight without changing the content geometry.
pub(crate) fn cockpit_pane_block(title: impl Into<Line<'static>>, focused: bool) -> Block<'static> {
    let mut title = title.into();
    if focused {
        title.spans.insert(
            0,
            Span::styled("▸ ", theme::accent().add_modifier(Modifier::BOLD)),
        );
    }
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

/// Keep the origin's one-line context strip, but clear its body while a modal
/// owns focus. The lower shell chrome is outside this area, so prompt and
/// navigation state remain visible without source text competing with the
/// modal border.
pub(crate) fn render_overlay_backdrop(frame: &mut Frame<'_>, area: Rect) {
    let body = overlay_body_area(area);
    frame.render_widget(Clear, body);
    let style = theme::muted()
        .bg(Color::Reset)
        .remove_modifier(Modifier::BOLD | Modifier::REVERSED);
    frame.buffer_mut().set_style(body, style);
}

pub(crate) fn overlay_body_area(area: Rect) -> Rect {
    Rect {
        y: area.y.saturating_add(1),
        height: area.height.saturating_sub(1),
        ..area
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{buffer::Buffer, widgets::Widget};

    #[test]
    fn focused_pane_title_has_a_non_color_marker() {
        let area = Rect::new(0, 0, 24, 3);
        let mut focused = Buffer::empty(area);
        cockpit_pane_block("DETAILS", true).render(area, &mut focused);
        let focused_text = focused
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();

        let mut idle = Buffer::empty(area);
        cockpit_pane_block("DETAILS", false).render(area, &mut idle);
        let idle_text = idle
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();

        assert!(focused_text.contains("▸ DETAILS"), "{focused_text}");
        assert!(!idle_text.contains('▸'), "{idle_text}");
    }
}
