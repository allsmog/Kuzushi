use super::*;

pub(super) fn replacement_lines(form: &LessonForm, area: Rect) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled("UNFINISHED LESSON", theme::accent())];
    lines.extend(wrapped(
        &format!("Requested: {}", form::form_title(form)),
        area.width,
        theme::primary(),
    ));
    lines.extend(wrapped(
        "D discards unsaved text and opens this form.",
        area.width,
        theme::warn(),
    ));
    lines.extend(wrapped(
        "Enter resumes · Esc returns to the list.",
        area.width,
        theme::primary(),
    ));
    lines
}
