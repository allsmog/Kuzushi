use super::*;
use crate::ui_view_models::study_context::context_actions;
use ratatui::layout::Margin;

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp, area: Rect, selected: usize) {
    let actions = context_actions(app);
    let area = menu_area(area, actions.len());
    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(
        Block::bordered()
            .title(" CONTEXT ACTIONS ")
            .border_style(theme::subtle()),
        area,
    );
    let inner = area.inner(Margin::new(1, 1));
    let height = inner.height.saturating_sub(2) as usize;
    let start = selected.saturating_sub(height.saturating_sub(1));
    let lines = action_rows(&actions, selected, start, height, inner.width as usize);
    frame.render_widget(
        Paragraph::new(lines),
        Rect {
            height: height as u16,
            ..inner
        },
    );
    let controls = Rect {
        y: inner.bottom().saturating_sub(2),
        height: 2,
        ..inner
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("↑↓ choose · Enter act · Esc back", theme::muted()),
            Line::styled("Checking makes no model request.", theme::muted()),
        ]),
        controls,
    );
}

fn menu_area(area: Rect, count: usize) -> Rect {
    let width = area.width.min(72);
    let ideal = count as u16 + 4;
    let height = if area.height.saturating_sub(ideal) <= 1 {
        area.height
    } else {
        ideal
    };
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn action_rows(
    actions: &[(crossterm::event::KeyCode, &str)],
    selected: usize,
    start: usize,
    height: usize,
    width: usize,
) -> Vec<Line<'static>> {
    actions
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(index, (_, label))| {
            let (marker, style) = if index == selected {
                ("▸", theme::selection())
            } else {
                (" ", theme::primary())
            };
            Line::styled(fit(&format!("{marker} {label}"), width), style)
        })
        .collect()
}
