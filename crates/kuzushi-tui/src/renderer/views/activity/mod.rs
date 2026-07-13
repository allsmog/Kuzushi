use super::*;

mod activity_lines;
mod dag_pane;
mod feed_pane;
mod render_activity_view;

pub(crate) use activity_lines::activity_lines;
pub(crate) use render_activity_view::render_activity_view;

fn activity_phase_strip_lines(
    model: &crate::ui_view_models::ActivityPhaseStripModel,
    width: u16,
) -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::styled(" PHASE ", theme::label()),
            Span::styled(model.phase.clone(), theme::warn()),
            Span::styled("  ·  CURRENT ", theme::subtle()),
            Span::styled(
                fit(&model.current, width.saturating_sub(32) as usize),
                theme::accent(),
            ),
        ]),
        Line::from(vec![
            Span::styled(" STAGE ", theme::label()),
            Span::styled(
                fit(&model.stage, width.saturating_sub(8) as usize),
                theme::primary(),
            ),
        ]),
    ]
}
