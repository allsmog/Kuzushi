use super::*;
pub(in crate::renderer) use super::*;

use self::chrome::*;
use self::shared::*;
use self::views::*;
use crate::app::{ScanPanelState, ShellApp, ShellView, ThreatView};
use crate::commands::{
    shell_command_specs, shell_help_examples, ShellCommandCategory, ShellCommandSpec,
};
use crate::theme;
pub(in crate::renderer) use chrome::*;
use kuzushi_core::modules::{ModuleKind, OptionSpec, OptionType};
use kuzushi_core::{
    proof_state_label, runtime_validation_label, sorted_finding_aliases, stable_finding_alias,
    AttachmentKind, Finding, Severity, SUPPORTED_ATTACHMENT_MODULES,
};
pub(in crate::renderer) use plain::*;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Modifier, Span, Style};
use ratatui::widgets::Paragraph;
pub(in crate::renderer) use render_app::*;
pub(in crate::renderer) use section_slot::*;
pub(in crate::renderer) use shared::*;
use std::collections::BTreeMap;
pub(in crate::renderer) use views::*;
mod chrome;
mod plain;
mod shared;
mod views;

mod render_app;
mod section_slot;
#[cfg(test)]
mod tests;
pub use plain::{render_plain_app, render_plain_command_result};
pub use render_app::render_app;
