use super::*;
use crate::app::lessons::{LessonContextBase, SelectedLesson};

pub(super) fn context_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    super::super::shell_view_lines::default_scrolled_lines(
        app,
        area,
        context_document_lines(app, area),
    )
}

pub(super) fn context_document_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let width = area.width;
    let mut lines = vec![Line::styled("LESSONS INTO CONTEXT", theme::accent())];
    let count = app.router.lessons.selected.len();
    lines.extend(wrapped(
        &format!(
            "Selected lessons: {count}. The copy replaces inherited lessons. Zero removes them."
        ),
        width,
        theme::primary(),
    ));
    if let Some(base) = &app.router.lessons.context_confirm {
        lines.extend(confirmation_lines(
            base,
            &app.router.lessons.selected,
            width,
        ));
    } else {
        lines.extend(context_rows(app, area));
    }
    lines.extend(notice_lines(app, width));
    lines
}

fn confirmation_lines(
    base: &LessonContextBase,
    selected: &[SelectedLesson],
    width: u16,
) -> Vec<Line<'static>> {
    let mut lines = wrapped(
        &format!("Base: {}", safe(&base.label)),
        width,
        theme::accent(),
    );
    for lesson in selected {
        lines.extend(wrapped(
            &format!(
                "  {} · revision {}",
                safe(&lesson.title),
                lesson.reference.revision
            ),
            width,
            theme::primary(),
        ));
    }
    lines.extend(wrapped("Create a new inactive context copy. The active context and finding decisions stay unchanged. Inspect and select the copy before approving scans. Changed or retired lessons block the copy.",width,theme::muted()));
    lines.extend(wrapped(
        "Enter creates copy · Esc chooses base · PgUp/PgDn read · Home/End first/last",
        width,
        theme::accent(),
    ));
    lines.extend(reference_lines(base, selected, width));
    lines
}

fn reference_lines(
    base: &LessonContextBase,
    selected: &[SelectedLesson],
    width: u16,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled("EXACT REVISIONS", theme::accent())];
    lines.extend(wrapped(
        &safe(&format!(
            "Base: {} / {}\n{}",
            base.reference.model_id, base.reference.revision_id, base.reference.sha256
        )),
        width,
        theme::muted(),
    ));
    for lesson in selected {
        lines.extend(wrapped(
            &safe(&format!(
                "Lesson: {} / revision {}\n{}",
                lesson.reference.lesson_id, lesson.reference.revision, lesson.reference.sha256
            )),
            width,
            theme::muted(),
        ));
    }
    lines
}

fn context_rows(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let catalog = crate::ui_view_models::study_context::context_catalog(app);
    let mut lines = wrapped(
        "Choose the exact base context · j/k select · Enter inspect confirmation · Esc back",
        area.width,
        theme::accent(),
    );
    if catalog.rows.len() <= 1 {
        lines.extend(wrapped(
            &format!("No immutable base context available. {}", catalog.status),
            area.width,
            theme::warn(),
        ));
        return lines;
    }
    let selected = app
        .router
        .lessons
        .context_cursor
        .max(1)
        .min(catalog.rows.len() - 1);
    let capacity = usize::from(area.height)
        .saturating_sub(lines.len() + 5)
        .max(1);
    let start = selected.saturating_sub(capacity / 2).max(1);
    for (index, row) in catalog.rows.iter().enumerate().skip(start).take(capacity) {
        lines.extend(context_row(&row.label, index == selected, area.width));
    }
    lines
}

fn context_row(label: &str, selected: bool, width: u16) -> Vec<Line<'static>> {
    wrapped(
        &format!("{} {}", if selected { "▸" } else { " " }, safe(label)),
        width,
        if selected {
            theme::accent()
        } else {
            theme::primary()
        },
    )
}

#[cfg(test)]
mod tests;
