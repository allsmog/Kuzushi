use super::*;
use ratatui::layout::Rect;
use ratatui::prelude::{Frame, Line, Span};
use ratatui::widgets::Paragraph;

mod compact;

use compact::operator_question_lines_for_height;

pub(in crate::renderer) fn operator_question_input_height(
    app: &crate::app::ShellApp,
    area: Rect,
) -> Option<u16> {
    if app.shell_view() != crate::ShellView::Activity {
        return None;
    }
    let card = app.activity()?.operator_question.as_ref()?;
    let desired = 7 + card.active_question().options.len() as u16 * 2;
    let reserve = if area.height <= 6 { 2 } else { 3 };
    let available = area.height.saturating_sub(reserve);
    let maximum = area.height.saturating_mul(45).div_ceil(100).max(6);
    Some(desired.min(maximum).min(available).max(available.min(5)))
}

pub(in crate::renderer) fn render_operator_question_input(
    frame: &mut Frame<'_>,
    area: Rect,
    app: &crate::app::ShellApp,
) -> bool {
    if app.shell_view() != crate::ShellView::Activity {
        return false;
    }
    let crate::ui_view_models::ActivityViewModel::Active(activity) =
        crate::ui_view_models::activity_view_model(app)
    else {
        return false;
    };
    let Some(card) = activity.operator_question() else {
        return false;
    };
    let hints = activity.operator_question_key_hints();
    render_operator_question(frame, area, card, &hints);
    true
}

fn render_operator_question(
    frame: &mut Frame<'_>,
    area: Rect,
    card: &crate::app::PendingOperatorQuestion,
    hints: &crate::ui_view_models::OperatorQuestionKeyHints,
) {
    let title = if card.is_submitting() {
        " SUBMITTING ".to_string()
    } else if let Some(seconds) = card
        .auto_resolution_seconds_remaining()
        .filter(|seconds| *seconds <= 10)
    {
        format!(" WAITING INPUT · {seconds}s ")
    } else {
        " WAITING INPUT ".to_string()
    };
    let block = cockpit_pane_block(Line::from(Span::styled(title, theme::warn())), true);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let lines = operator_question_lines_for_height(
        card,
        hints,
        inner.width as usize,
        inner.height as usize,
    );
    frame.render_widget(Paragraph::new(lines), inner);
}

pub(super) fn operator_question_lines(
    card: &crate::app::PendingOperatorQuestion,
    hints: &crate::ui_view_models::OperatorQuestionKeyHints,
    width: usize,
) -> Vec<Line<'static>> {
    let question = card.active_question();
    let mut lines = question_header_lines(card, width);
    for index in 0..question.options.len() {
        lines.extend(question_option_lines(card, index, width));
    }
    lines.push(other_answer_line(card, hints, width));
    lines.push(question_key_hint(card, hints, width));
    lines
}

fn question_header_lines(
    card: &crate::app::PendingOperatorQuestion,
    width: usize,
) -> Vec<Line<'static>> {
    let request = card.request();
    let question = card.active_question();
    vec![
        Line::from(vec![
            Span::styled(
                format!(
                    "{}  {}/{}  ",
                    question.header.to_ascii_uppercase(),
                    card.active_question_index() + 1,
                    request.questions.len()
                ),
                theme::heading(),
            ),
            Span::styled(
                fit(&format!("run {}", request.run_id), width.saturating_sub(20)),
                theme::muted(),
            ),
        ]),
        Line::from(Span::styled(fit(&question.prompt, width), theme::primary())),
        Line::default(),
    ]
}

fn question_option_lines(
    card: &crate::app::PendingOperatorQuestion,
    index: usize,
    width: usize,
) -> [Line<'static>; 2] {
    let option = &card.active_question().options[index];
    let selected = index == card.selected_option_index() && card.other_editor().is_none();
    let marker = if selected { "▸" } else { " " };
    let recommendation = if option.recommended {
        "  recommended"
    } else {
        ""
    };
    let style = if selected {
        theme::accent()
    } else {
        theme::primary()
    };
    [
        Line::from(vec![
            Span::styled(format!("{marker} {}. {}", index + 1, option.label), style),
            Span::styled(recommendation, theme::success()),
        ]),
        Line::from(Span::styled(
            fit(&format!("    {}", option.description), width),
            theme::muted(),
        )),
    ]
}

fn other_answer_line(
    card: &crate::app::PendingOperatorQuestion,
    hints: &crate::ui_view_models::OperatorQuestionKeyHints,
    width: usize,
) -> Line<'static> {
    match card.other_editor() {
        Some(editor) => {
            let cursor = card
                .other_cursor()
                .unwrap_or_default()
                .min(editor.chars().count());
            let mut chars = editor.chars().collect::<Vec<_>>();
            chars.insert(cursor, '▏');
            Line::from(vec![
                Span::styled("▸ Other › ", theme::accent()),
                Span::styled(
                    fit(
                        &chars.into_iter().collect::<String>(),
                        width.saturating_sub(10),
                    ),
                    theme::primary(),
                ),
            ])
        }
        None => Line::from(Span::styled(
            hints.other_binding.as_ref().map_or_else(
                || "  Other  (unbound)".to_string(),
                |binding| format!("  Other  ({binding} to type)"),
            ),
            theme::muted(),
        )),
    }
}

fn question_key_hint(
    card: &crate::app::PendingOperatorQuestion,
    hints: &crate::ui_view_models::OperatorQuestionKeyHints,
    width: usize,
) -> Line<'static> {
    let segments = if card.other_editor().is_some() {
        &hints.editor_segments
    } else {
        &hints.segments
    };
    Line::from(Span::styled(
        fit(&segments.join(" · "), width),
        theme::label(),
    ))
}

#[cfg(test)]
mod tests;
