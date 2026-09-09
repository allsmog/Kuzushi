use super::*;
pub(in crate::renderer) use super::*;
use crate::ui_view_models::JourneyPhaseTone;
use ratatui::style::Style;

pub(in crate::renderer) use activity::*;
pub(crate) use activity::{activity_output_scroll, ActivityOutputScroll};
pub(in crate::renderer) use campaign::*;
pub(in crate::renderer) use catalog::*;
pub(in crate::renderer) use chat::*;
pub(in crate::renderer) use editor::*;
pub(crate) use help::logs_reader_scroll;
pub(in crate::renderer) use help::*;
pub(in crate::renderer) use module::*;
pub(crate) use onboarding::planning_option_error_scroll;
pub(in crate::renderer) use onboarding::*;
pub(in crate::renderer) use options::*;
pub(in crate::renderer) use patch::*;
pub(in crate::renderer) use pwn::*;
pub(crate) use report::report_offset_after_page;
pub(in crate::renderer) use report::*;
pub(in crate::renderer) use runs::*;
pub(crate) use runs::{run_artifact_max_scroll, run_artifact_page_rows};
pub(crate) use scene::entry_point_page_scroll;
pub(in crate::renderer) use scene::*;
pub(in crate::renderer) use shell_view_lines::*;
pub(crate) use system::keymap_reader_scroll;
pub(crate) use system::quit_disclosure_viewport;
pub(in crate::renderer) use system::*;
pub(in crate::renderer) use threat::*;
pub(in crate::renderer) use viewport_lines::*;
pub(crate) use workbench::workbench_phase_plan_for_app;
pub(in crate::renderer) use workbench::*;
pub(in crate::renderer) use workspace::*;
mod activity;
mod campaign;
mod catalog;
mod chat;
mod editor;
mod help;
mod module;
mod onboarding;
mod options;
mod patch;
mod pwn;
mod report;
mod runs;
mod scene;
mod system;
mod threat;
mod workbench;
mod workspace;

mod shell_view_lines;
mod viewport_lines;
pub(super) use activity::*;
pub(super) use campaign::*;
pub(super) use catalog::*;
pub(super) use chat::*;
pub(super) use editor::*;
pub(super) use help::*;
pub(super) use module::*;
pub(super) use onboarding::*;
pub(super) use options::*;
pub(super) use patch::*;
pub(super) use pwn::*;
pub(super) use report::*;
pub(super) use runs::*;
pub(super) use scene::*;
pub(super) use system::*;
pub(super) use threat::*;
pub(super) use workbench::*;
pub(super) use workspace::*;

pub(in crate::renderer) fn journey_phase_tone_style(tone: JourneyPhaseTone) -> Style {
    match tone {
        JourneyPhaseTone::Success => theme::success(),
        JourneyPhaseTone::Warn => theme::warn(),
        JourneyPhaseTone::Danger => theme::danger(),
        JourneyPhaseTone::Muted => theme::muted(),
        JourneyPhaseTone::Subtle => theme::subtle(),
    }
}
