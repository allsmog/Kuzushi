use super::*;

pub(super) fn operator_question_lines_for_height(
    card: &crate::app::PendingOperatorQuestion,
    hints: &crate::ui_view_models::OperatorQuestionKeyHints,
    width: usize,
    height: usize,
) -> Vec<Line<'static>> {
    let full = operator_question_lines(card, hints, width);
    if full.len() <= height {
        return full;
    }
    compact_operator_question_lines(card, hints, width, height)
}

fn compact_operator_question_lines(
    card: &crate::app::PendingOperatorQuestion,
    hints: &crate::ui_view_models::OperatorQuestionKeyHints,
    width: usize,
    height: usize,
) -> Vec<Line<'static>> {
    if height == 0 {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut body_budget = height.saturating_sub(1);
    append_compact_question_intro(&mut lines, card, width, &mut body_budget);
    append_compact_question_control(&mut lines, card, hints, width, body_budget);
    lines.truncate(height.saturating_sub(1));
    lines.push(question_key_hint(card, hints, width));
    lines
}

fn append_compact_question_intro(
    lines: &mut Vec<Line<'static>>,
    card: &crate::app::PendingOperatorQuestion,
    width: usize,
    budget: &mut usize,
) {
    if *budget >= 3 {
        lines.push(compact_question_header(card, width));
        *budget -= 1;
    }
    if *budget > 0 {
        lines.push(Line::from(Span::styled(
            fit(&card.active_question().prompt, width),
            theme::primary(),
        )));
        *budget -= 1;
    }
}

fn append_compact_question_control(
    lines: &mut Vec<Line<'static>>,
    card: &crate::app::PendingOperatorQuestion,
    hints: &crate::ui_view_models::OperatorQuestionKeyHints,
    width: usize,
    budget: usize,
) {
    if budget == 0 {
        return;
    }
    if card.other_editor().is_some() {
        lines.push(other_answer_line(card, hints, width));
        return;
    }
    let options = compact_question_option_lines(card, width, budget);
    let used = options.len();
    lines.extend(options);
    if used < budget {
        lines.push(other_answer_line(card, hints, width));
    }
}

fn compact_question_header(
    card: &crate::app::PendingOperatorQuestion,
    width: usize,
) -> Line<'static> {
    let question = card.active_question();
    let text = format!(
        "{}  {}/{}  ·  run {}",
        question.header.to_ascii_uppercase(),
        card.active_question_index() + 1,
        card.request().questions.len(),
        card.request().run_id,
    );
    Line::from(Span::styled(fit(&text, width), theme::heading()))
}

fn compact_question_option_lines(
    card: &crate::app::PendingOperatorQuestion,
    width: usize,
    budget: usize,
) -> Vec<Line<'static>> {
    let len = card.active_question().options.len();
    let visible = budget.min(len);
    let cursor = card.selected_option_index();
    let start = cursor.saturating_sub(visible / 2).min(len - visible);
    (start..start + visible)
        .map(|index| compact_question_option_line(card, index, width))
        .collect()
}

fn compact_question_option_line(
    card: &crate::app::PendingOperatorQuestion,
    index: usize,
    width: usize,
) -> Line<'static> {
    let option = &card.active_question().options[index];
    let selected = index == card.selected_option_index();
    let marker = if selected { "▸" } else { " " };
    let recommendation = if option.recommended {
        " · recommended"
    } else {
        ""
    };
    let style = if selected {
        theme::accent()
    } else {
        theme::muted()
    };
    Line::from(Span::styled(
        fit(
            &format!("{marker} {}. {}{recommendation}", index + 1, option.label),
            width,
        ),
        style,
    ))
}
