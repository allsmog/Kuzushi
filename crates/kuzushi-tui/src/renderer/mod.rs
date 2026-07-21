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
pub(in crate::renderer) use section_slot::*;
pub(in crate::renderer) use shared::*;
pub(crate) use views::workbench_phase_plan_for_app;
pub(in crate::renderer) use views::*;
mod chrome;
mod plain;
pub(crate) mod shared;
mod views;

#[cfg(test)]
mod phase_composition_contract;
mod render_app;
mod section_slot;
#[cfg(test)]
mod failure_coverage;
#[cfg(test)]
mod plain_parity;
#[cfg(test)]
mod surface_lints;
#[cfg(test)]
mod tests;
pub use plain::{render_plain_app, render_plain_command_result};
pub use render_app::render_app;
