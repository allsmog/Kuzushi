use super::*;

pub(in crate::renderer) fn render_lines(
    frame: &mut Frame<'_>,
    area: Rect,
    lines: Vec<Line<'static>>,
) {
    if area.height == 0 {
        return;
    }
    frame.render_widget(Paragraph::new(lines), area);
}
