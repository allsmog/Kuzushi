use super::*;

pub(crate) fn run_artifact_page_rows(app: &ShellApp) -> Option<usize> {
    run_artifact_area(app).map(|area| reader_body_rows(app, area))
}

fn reader_body_rows(app: &ShellApp, area: Rect) -> usize {
    let reserved = if app.shell_view() == ShellView::RunDiff {
        3
    } else {
        0
    };
    usize::from(area.height).saturating_sub(reserved).max(1)
}

pub(crate) fn run_artifact_max_scroll(app: &ShellApp) -> Option<u16> {
    let area = run_artifact_area(app)?;
    let lines = match app.shell_view() {
        ShellView::Replay => replay_lines(app, area, app.router.replay().run_id()),
        ShellView::Trace => trace_lines(app, area, app.router.trace().run_id()),
        ShellView::FailureHandoff => failure_handoff_lines(app, area),
        ShellView::RunDiff => run_diff_lines(
            app,
            area,
            app.router.run_diff().left(),
            app.router.run_diff().right(),
        ),
        _ => return None,
    };
    if lines.len() <= usize::from(area.height) {
        return Some(0);
    }
    let pinned = if app.shell_view() == ShellView::RunDiff {
        2
    } else {
        0
    };
    let max = lines
        .len()
        .saturating_sub(pinned)
        .saturating_sub(reader_body_rows(app, area));
    Some(max.min(u16::MAX as usize) as u16)
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
