use super::*;
pub(in crate::renderer) use super::*;

mod detail_pane;
mod panes;
mod render_workbench_view;

pub(in crate::renderer) use render_workbench_view::*;
pub(crate) use render_workbench_view::{render_workbench_view, workbench_lines};
