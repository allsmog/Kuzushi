use super::*;
use crate::app::{ContextComparisonView, StudyContextComparison};
use crate::ui_view_models::study_context::comparison;

pub(super) fn render(frame: &mut Frame<'_>, area: Rect, context: &StudyContextComparison) {
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::subtle())
            .title(Span::styled(" COMPARE SAVED CONTEXT ", theme::heading())),
        area,
    );
    let layout = comparison::layout(area);
    render_tabs(frame, layout.tabs, context.view);
    render_list(frame, layout.list, context);
    render_detail(frame, layout.detail, context);
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("↑↓ choose PgUp/Dn Home/End read", theme::muted()),
            Line::styled(controls(context), theme::accent()),
        ]),
        layout.controls,
    );
}

fn render_tabs(frame: &mut Frame<'_>, area: Rect, selected: ContextComparisonView) {
    let spans = ContextComparisonView::ALL
        .into_iter()
        .flat_map(|view| {
            let style = if view == selected {
                theme::selection()
            } else {
                theme::muted()
            };
            [
                Span::styled(format!(" {} ", comparison::label(view)), style),
                Span::raw(" "),
            ]
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_list(frame: &mut Frame<'_>, area: Rect, context: &StudyContextComparison) {
    let entries = comparison::entries(context, context.view);
    let selected = context
        .cursor()
        .selected
        .min(entries.len().saturating_sub(1));
    let start = selected.saturating_sub((area.height as usize).saturating_sub(1));
    let lines = entries
        .iter()
        .enumerate()
        .skip(start)
        .take(area.height as usize)
        .map(|(index, entry)| {
            let marker = if index == selected { "▸" } else { " " };
            let style = if index == selected {
                theme::selection()
            } else {
                theme::muted()
            };
            Line::styled(
                fit(
                    &format!(
                        "{marker} {}/{} {}",
                        index + 1,
                        entries.len(),
                        comparison::title(entry)
                    ),
                    area.width as usize,
                ),
                style,
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_detail(frame: &mut Frame<'_>, area: Rect, context: &StudyContextComparison) {
    let lines = comparison::selected_lines(context, area.width as usize);
    let offset = context
        .cursor()
        .scroll
        .min(lines.len().saturating_sub(area.height as usize));
    let lines = lines
        .into_iter()
        .skip(offset)
        .take(area.height as usize)
        .map(|line| Line::styled(line, theme::primary()))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn controls(context: &StudyContextComparison) -> &'static str {
    if context.error.is_some() {
        return "Tab view · Enter retry · Esc back";
    }
    if context.ready() {
        return "Tab view · a use in study · Esc back";
    }
    "Reading parent · Esc back"
}
