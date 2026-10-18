use super::*;

pub(crate) struct LessonReaderScroll {
    pub(crate) max_offset: u16,
    pub(crate) page_rows: u16,
}

pub(crate) fn lesson_reader_scroll(app: &ShellApp) -> Option<LessonReaderScroll> {
    if !app.lesson_reading_is_active() {
        return None;
    }
    let viewport = app.viewport();
    let full = Rect::new(0, 0, viewport.columns, viewport.rows);
    let primary = crate::renderer::primary_body_area(app, full);
    let area = crate::ui_view_models::answers_layout(app, primary).workspace;
    let total = reading_document(app, area)?.len();
    Some(LessonReaderScroll {
        max_offset: total
            .saturating_sub(usize::from(area.height))
            .min(usize::from(u16::MAX)) as u16,
        page_rows: area.height.max(1),
    })
}

fn reading_document(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    if app.router.lessons.context_selecting {
        return Some(context::context_document_lines(app, area));
    }
    if app.router.lessons.form_visible {
        return app
            .router
            .lessons
            .form
            .as_ref()
            .map(|form| form::confirmation_document_lines(app, form, area));
    }
    Some(browser_document_lines(app, area))
}
