use super::*;

struct RecordedSelection<'a> {
    record: &'a FindingLesson,
    outside_page: bool,
}

fn recorded_selection(app: &ShellApp) -> Option<RecordedSelection<'_>> {
    let ViewDataState::Ready(Ok(page)) = app.lesson_page() else {
        return None;
    };
    let record = app.pinned_lesson_snapshot()?;
    let visible = app
        .lesson_cursor(&page)
        .and_then(|index| page.rows.get(index));
    if visible.is_some_and(|visible| visible.revision >= record.revision) {
        return None;
    }
    Some(RecordedSelection {
        record,
        outside_page: visible.is_none(),
    })
}

pub(super) fn recorded_heading(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let Some(selection) = recorded_selection(app) else {
        return Vec::new();
    };
    let heading = if selection.outside_page {
        "Recorded selection outside this page"
    } else {
        "Recorded revision newer than this page"
    };
    let record = selection.record;
    let mut lines = wrapped(heading, width, theme::warn());
    lines.extend(wrapped(
        &format!(
            "{:?} · {} · v{}",
            record.state,
            safe(&record.content.title),
            record.revision
        ),
        width,
        theme::primary(),
    ));
    lines.extend(wrapped(
        &format!("Lesson: {}", safe(&record.id)),
        width,
        theme::muted(),
    ));
    lines
}

pub(super) fn recorded_detail_lines(app: &ShellApp, width: u16) -> Option<Vec<Line<'static>>> {
    let selection = recorded_selection(app)?;
    let mut lines = wrapped(
        "Showing its recorded revision. A newer change can block saving. j/k chooses a visible lesson; [/] changes pages.",
        width,
        theme::muted(),
    );
    lines.extend(detail_lines(selection.record, width));
    Some(lines)
}

pub(super) fn missing_selection_lines(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    wrapped(&format!("Requested lesson {} is outside this page. Refresh or choose a page before review. j/k explicitly selects another visible lesson.",safe(app.router.lessons.pinned_id.as_deref().unwrap_or("unrecorded"))),width,theme::warn())
}

pub(super) fn empty_page_lines(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    recorded_detail_lines(app, width).unwrap_or_else(|| {
        let hint = if app.router.lessons.offset == 0 {
            "No saved lessons. Open a confirmed finding in Review, then use lessons and n to draft from that exact generation."
        } else {
            "No lessons on this page. Press [ for the previous page or R to refresh."
        };
        wrapped(hint, width, theme::muted())
    })
}
