use super::*;

pub(crate) fn replay_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    pinned_document_viewport_lines(
        replay_lines(app, area, app.router.replay().run_id()),
        area.height,
        app.router.default_scroll().offset() as usize,
        1,
    )
}

pub(crate) fn run_artifact_page_rows(app: &ShellApp) -> Option<usize> {
    run_artifact_area(app).map(|area| reader_body_rows(app, area))
}

fn reader_body_rows(app: &ShellApp, area: Rect) -> usize {
    let pinned = reader_pinned_rows(app.shell_view());
    let reserved = if pinned == 0 { 0 } else { pinned + 1 };
    usize::from(area.height).saturating_sub(reserved).max(1)
}

fn reader_pinned_rows(view: ShellView) -> usize {
    match view {
        ShellView::RunDiff => 2,
        ShellView::Replay => 1,
        _ => 0,
    }
}

pub(crate) fn run_artifact_max_scroll(app: &ShellApp) -> Option<u16> {
    let area = run_artifact_area(app)?;
    let lines = reader_document(app, area)?;
    if lines.len() <= usize::from(area.height) {
        return Some(0);
    }
    let max = lines
        .len()
        .saturating_sub(reader_pinned_rows(app.shell_view()))
        .saturating_sub(reader_body_rows(app, area));
    Some(max.min(u16::MAX as usize) as u16)
}

fn reader_document(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    match app.shell_view() {
        ShellView::Replay => Some(replay_lines(app, area, app.router.replay().run_id())),
        ShellView::Trace => Some(trace_lines(app, area, app.router.trace().run_id())),
        _ => other_reader_document(app, area),
    }
}

fn other_reader_document(app: &ShellApp, area: Rect) -> Option<Vec<Line<'static>>> {
    Some(match app.shell_view() {
        ShellView::FailureHandoff => failure_handoff_lines(app, area),
        ShellView::RunDiff => run_diff_lines(
            app,
            area,
            app.router.run_diff().left(),
            app.router.run_diff().right(),
        ),
        _ => return None,
    })
}

fn run_artifact_area(app: &ShellApp) -> Option<Rect> {
    if !matches!(
        app.shell_view(),
        ShellView::Replay | ShellView::Trace | ShellView::FailureHandoff | ShellView::RunDiff
    ) {
        return None;
    }
    let viewport = app.viewport();
    let full = Rect::new(0, 0, viewport.columns, viewport.rows);
    let primary = crate::renderer::primary_body_area(app, full);
    Some(crate::ui_view_models::answers_layout(app, primary).workspace)
}
