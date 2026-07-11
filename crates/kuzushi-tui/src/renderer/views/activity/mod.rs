use super::*;

mod activity_lines;
mod dag_pane;
mod feed_pane;
mod render_activity_view;

pub(crate) use activity_lines::activity_lines;
pub(crate) use render_activity_view::render_activity_view;

fn activity_phase_header_lines(
    header: &crate::ui_view_models::EngagementHeaderModel,
    area: Rect,
) -> Vec<Line<'static>> {
    let mut lines = phase_header_lines(header, &[], area.width as usize);
    if area.height < 24 && lines.len() > 2 {
        lines.remove(1);
    }
    lines
}
