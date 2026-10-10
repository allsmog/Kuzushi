//! Short terminals keep decisions visible; Tab opens complete explanations.
use super::*;

pub(super) fn needs_dense_overview(
    app: &ShellApp,
    model: &crate::ui_view_models::SetupReadinessModel,
    area: Rect,
) -> bool {
    let compact = area.width < 72;
    let rows = setup_readiness_lines(app, &model.rows, area.width as usize, compact).len();
    let summary = setup_summary_lines(model, area.width as usize).len();
    let header = if compact { 1 } else { 3 };
    rows + summary + header + 1 > usize::from(area.height)
}

pub(super) fn dense_lines(
    app: &ShellApp,
    model: &crate::ui_view_models::SetupReadinessModel,
    area: Rect,
) -> Vec<Line<'static>> {
    let width = area.width as usize;
    let cursor = app.router.setup().cursor();
    let mut lines = vec![divider("SETUP · READINESS", area.width)];
    let Some((start, rest)) = model.rows.split_last() else {
        return lines;
    };
    let capacity = usize::from(area.height).saturating_sub(2);
    let range = readiness_range(rest.len(), capacity, cursor);
    lines.extend(
        rest[range.clone()]
            .iter()
            .enumerate()
            .map(|(offset, row)| setup_row_line(row, range.start + offset == cursor, width, true)),
    );
    lines.push(setup_row_line(start, cursor == rest.len(), width, true));
    lines
}

fn readiness_range(total: usize, capacity: usize, cursor: usize) -> std::ops::Range<usize> {
    let count = capacity.min(total);
    let start = viewport_start_for_cursor(total, count, cursor.min(total.saturating_sub(1)));
    start..start.saturating_add(count).min(total)
}
