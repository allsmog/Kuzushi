use super::*;
pub(in crate::renderer) use super::*;

mod detail_pane;
pub(in crate::renderer) mod guided_scan;
mod panes;
mod phase_pages;
mod render_workbench_view;

pub(in crate::renderer) use guided_scan::{guided_question_height, render_guided_question};
pub(in crate::renderer::views) use phase_pages::{
    phase_cockpit_plain_lines, phase_header_lines, render_phase_cockpit_body, PhaseRenderState,
};
pub(in crate::renderer) use render_workbench_view::*;
pub(crate) use render_workbench_view::{
    render_workbench_view, workbench_lines, workbench_phase_plan_for_app,
};
