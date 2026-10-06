use super::*;
pub(in crate::renderer) use super::*;

use self::chrome::*;
use self::shared::*;
use self::views::*;
use crate::app::{ShellApp, ThreatView};
use crate::theme;
pub(in crate::renderer) use chrome::*;
pub(in crate::renderer) use plain::*;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Modifier, Span, Style};
use ratatui::widgets::Paragraph;
pub(in crate::renderer) use render_app::*;
pub(crate) use render_app::{
    primary_body_area, workbench_primary_area, workbench_scroll_page_rows,
};
pub(in crate::renderer) use section_slot::*;
pub(in crate::renderer) use shared::*;
pub(crate) use views::campaign_reader_scroll;
pub(crate) use views::entry_point_page_scroll;
pub(crate) use views::keymap_reader_scroll;
pub(crate) use views::logs_reader_scroll;
pub(crate) use views::planning_option_error_scroll;
pub(crate) use views::quit_disclosure_viewport;
pub(crate) use views::report_offset_after_page;
pub(crate) use views::workbench_phase_plan_for_app;
pub(in crate::renderer) use views::*;
pub(crate) use views::{activity_output_scroll, ActivityOutputScroll};
pub(crate) use views::{run_artifact_max_scroll, run_artifact_page_rows};
mod allowance_review;
mod answers;
mod chrome;
mod context_generation;
mod paste_inspection;
mod scope_review;
mod study_config;
mod study_context;
mod study_engines;
pub(crate) use answers::{
    answer_body_area, answer_plain_lines, render_answer_prompt, render_answers,
};
mod plain;
pub(crate) mod shared;
mod views;

#[cfg(test)]
mod failure_coverage;
#[cfg(test)]
mod phase_composition_contract;
#[cfg(test)]
mod plain_parity;
mod render_app;
mod section_slot;
#[cfg(test)]
pub(crate) mod surface_lints;
#[cfg(test)]
mod tests;
pub use plain::{render_plain_app, render_plain_command_result};
pub use render_app::render_app;
