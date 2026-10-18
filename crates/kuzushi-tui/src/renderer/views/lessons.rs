use super::*;
use crate::app::{
    lessons::{LessonForm, LessonFormAction},
    ShellApp, ViewDataState,
};
use kuzushi_core::findings::FindingLesson;
mod context;
mod form;
mod generation;
mod reader;
mod replacement;
pub(crate) use reader::lesson_reader_scroll;

pub(super) fn lesson_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    if let Some(lines) = modal_lines(app, area) {
        return lines;
    }
    super::shell_view_lines::default_scrolled_lines(app, area, browser_document_lines(app, area))
}

fn modal_lines(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    if let Some(form) = &app.router.lessons.replacement_form {
        return Some(replacement::replacement_lines(form, area));
    }
    if app.router.lessons.context_selecting {
        return Some(context::context_lines(app, area));
    }
    if app.router.lessons.form_visible {
        return app
            .router
            .lessons
            .form
            .as_ref()
            .map(|draft| form::form_lines(app, draft, area));
    }
    None
}

fn browser_document_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled("REUSABLE LESSONS", theme::accent())];
    lines.extend(browser_actions(area.width));
    lines.extend(browser_lines(app, area));
    lines.extend(notice_lines(app, area.width));
    lines
}

fn browser_actions(width: u16) -> Vec<Line<'static>> {
    if width < 60 {
        return wrapped(
            "n draft · g model · a/r/t review\nu copy · e edit · d draft · c clear",
            width,
            theme::accent(),
        );
    }
    let mut lines = vec![Line::raw("Draft → human review → explicit context copy")];
    lines.extend(wrapped("n draft · g budgeted model draft · e edit · a accept · r reject · t retire · Space select · u context copy · c clear",width,theme::accent()));
    lines
}

fn browser_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let page = match app.lesson_page() {
        ViewDataState::Ready(Ok(page)) => page,
        ViewDataState::Ready(Err(error)) => {
            return wrapped(
                &format!("Lessons unavailable: {error}. R refreshes."),
                area.width,
                theme::warn(),
            )
        }
        _ => return vec![Line::raw("Loading saved lessons...")],
    };
    let mut lines = vec![Line::raw(format!(
        "{} saved · {} selected · page {}{}",
        page.rows.len(),
        app.router.lessons.selected.len(),
        page.offset / 50 + 1,
        if page.has_more {
            " · more available"
        } else {
            ""
        }
    ))];
    if page.rows.is_empty() {
        lines.extend(wrapped("No saved lessons. Open a confirmed finding in Review, then use lessons and n to draft from that exact generation.",area.width,theme::muted()));
        return lines;
    }
    lines.extend(lesson_rows(app, area, &page));
    lines
}

fn lesson_rows(
    app: &ShellApp,
    area: Rect,
    page: &kuzushi_core::findings::FindingLessonPage,
) -> Vec<Line<'static>> {
    let Some(selected) = app.lesson_cursor(page) else {
        return wrapped(&format!("Requested lesson {} is outside this page. Refresh or choose a page before review. j/k explicitly selects another visible lesson.",app.router.lessons.pinned_id.as_deref().unwrap_or("unrecorded")),area.width,theme::warn());
    };
    let capacity = usize::from(area.height).saturating_sub(10).clamp(1, 5);
    let start = selected
        .saturating_sub(capacity / 2)
        .min(page.rows.len().saturating_sub(capacity));
    let mut lines = Vec::new();
    for (index, record) in page.rows.iter().enumerate().skip(start).take(capacity) {
        lines.extend(lesson_row(app, record, index == selected, area.width));
    }
    lines.extend(detail_lines(&page.rows[selected], area.width));
    lines
}

fn lesson_row(
    app: &ShellApp,
    record: &FindingLesson,
    selected: bool,
    width: u16,
) -> Vec<Line<'static>> {
    let marked = app
        .router
        .lessons
        .selected
        .iter()
        .any(|lesson| lesson.reference.lesson_id == record.id);
    wrapped(
        &format!(
            "{} {} {:?} · {} · v{}",
            if selected { "▸" } else { " " },
            if marked { "[x]" } else { "[ ]" },
            record.state,
            safe(&record.content.title),
            record.revision
        ),
        width,
        if selected {
            theme::accent()
        } else {
            theme::primary()
        },
    )
}

pub(super) fn detail_lines(record: &FindingLesson, width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled("SELECTED LESSON", theme::accent())];
    let origin = &record.origin;
    lines.extend(generation_receipt_lines(record, width));
    for (label, text) in [
        ("Lesson", record.content.text.as_str()),
        ("Applies", &record.content.applicability),
        ("Limits", &record.content.limitations),
    ] {
        lines.extend(wrapped(
            &format!("{label}: {}", safe(text)),
            width,
            theme::primary(),
        ));
    }
    lines.extend(wrapped(&format!("Origin: generation #{} · run {} · confirmation #{}\nObservation event {} · snapshot {}\nSource revision: {}\nLesson {} revision {}\nHistorical guidance. Other source revisions require independent review.",origin.finding.finding_id,origin.finding.run_id.as_deref().unwrap_or("unrecorded"),origin.decision.id,origin.observation_seq,origin.snapshot_hash,origin.source_git.as_ref().map(|git|format!("{} · {}",git.sha,if git.dirty {"dirty"} else {"clean"})).unwrap_or("unrecorded".into()),record.id,record.revision),width,theme::muted()));
    if let Some(note) = &record.review_note {
        lines.extend(wrapped(
            &format!("Review reason: {}", safe(note)),
            width,
            theme::primary(),
        ));
    }
    lines
}

fn generation_receipt_lines(record: &FindingLesson, width: u16) -> Vec<Line<'static>> {
    let Some(receipt) = &record.generation else {
        return wrapped("Draft source: operator text", width, theme::muted());
    };
    generation::receipt_lines(receipt, width)
}

pub(super) fn notice_lines(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let mut lines = app
        .router
        .lessons
        .notice
        .as_ref()
        .map(|text| wrapped(&safe(text), width, theme::warn()))
        .unwrap_or_default();
    if let Some(reference) = &app.router.lessons.saved_context {
        lines.extend(wrapped(
            &format!(
                "Saved context: {} / {}",
                reference.model_id, reference.revision_id
            ),
            width,
            theme::primary(),
        ));
    }
    lines
}

pub(super) fn wrapped(text: &str, width: u16, style: Style) -> Vec<Line<'static>> {
    wrap_text(text, usize::from(width).max(1))
        .into_iter()
        .map(|line| Line::styled(line, style))
        .collect()
}

pub(super) fn safe(text: &str) -> String {
    text.split('\n')
        .map(|line| kuzushi_core::run_lifecycle::SafeText::operator_visible(line).to_string())
        .collect::<Vec<_>>()
        .join("\n")
}
