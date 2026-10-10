use super::*;
use crate::app::StudyContextComparison;

pub(super) fn render(frame: &mut Frame<'_>, area: Rect, comparison: &StudyContextComparison) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" COMPARE CONTEXT TEXT ");
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);
    let lines =
        crate::ui_view_models::study_context::comparison_lines(comparison, inner.width as usize);
    let height = inner.height.saturating_sub(2) as usize;
    let offset = comparison.scroll.min(lines.len().saturating_sub(height));
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(offset)
                .take(height)
                .map(Line::from)
                .collect::<Vec<_>>(),
        ),
        Rect {
            height: height as u16,
            ..inner
        },
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("PgUp/Dn read · Esc back"),
            Line::from(comparison_action(comparison)),
        ]),
        Rect {
            y: inner.bottom().saturating_sub(2),
            height: 2,
            ..inner
        },
    );
}

fn comparison_action(comparison: &StudyContextComparison) -> &'static str {
    if comparison.error.is_some() {
        return "Enter retry local parent read";
    }
    if comparison.differences.is_some() {
        return "a use inspected candidate for study";
    }
    "Reading parent · selection unchanged"
}
