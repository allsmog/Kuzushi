use kuzushi_core::modules::{ModuleKind, OptionSpec, OptionType};
use kuzushi_core::{
    proof_state_label, runtime_validation_label, sorted_finding_aliases, stable_finding_alias,
    AttachmentKind, Finding, Severity, SUPPORTED_ATTACHMENT_MODULES,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::{Frame, Line, Modifier, Span, Style};
use ratatui::widgets::Paragraph;

use crate::app::{ScanPanelState, ShellApp, ShellView, ThreatView};
use crate::commands::{
    shell_command_specs, shell_help_examples, ShellCommandCategory, ShellCommandSpec,
};
use crate::theme;

mod chrome;
mod plain;
mod shared;
mod views;

pub use plain::{render_plain_app, render_plain_command_result};

use self::chrome::*;
use self::shared::*;
use self::views::*;

pub fn render_app(frame: &mut Frame<'_>, app: &ShellApp) {
    let area = frame.area();
    if area.height == 0 || area.width == 0 {
        return;
    }

    let prompt_height = 1;
    let transcript_height = if matches!(app.shell_view, ShellView::ModuleRun) {
        0
    } else if area.height >= 12 {
        2
    } else {
        0
    };
    let keybind_height = if area.height >= 8 { 2 } else { 0 };
    let status_height = if area.height >= 6 { 1 } else { 0 };
    let throttle_height = if app.advisory.throttle.is_some() && area.height >= 5 {
        1
    } else {
        0
    };
    let budget_height = if app.is_budget_halted() && area.height >= 5 {
        2
    } else {
        0
    };
    let plan_height = plan_card_height(app, area);
    let threat_patch_height = threat_patch_card_height(app, area);
    let confirm_height = confirm_card_height(app, area);
    let fixed_height = prompt_height
        + transcript_height
        + keybind_height
        + status_height
        + throttle_height
        + budget_height
        + plan_height
        + threat_patch_height
        + confirm_height;
    let max_view_height = area.height.saturating_sub(fixed_height).max(1);
    let view_area = Rect {
        height: max_view_height,
        ..area
    };
    let view_lines = shell_view_lines(app, view_area);
    let view_height = (view_lines.len() as u16).clamp(1, max_view_height);

    let mut constraints = vec![Constraint::Length(view_height), Constraint::Min(0)];
    if throttle_height > 0 {
        constraints.push(Constraint::Length(throttle_height));
    }
    if status_height > 0 {
        constraints.push(Constraint::Length(status_height));
    }
    if keybind_height > 0 {
        constraints.push(Constraint::Length(keybind_height));
    }
    if budget_height > 0 {
        constraints.push(Constraint::Length(budget_height));
    }
    if plan_height > 0 {
        constraints.push(Constraint::Length(plan_height));
    }
    if threat_patch_height > 0 {
        constraints.push(Constraint::Length(threat_patch_height));
    }
    if confirm_height > 0 {
        constraints.push(Constraint::Length(confirm_height));
    }
    if transcript_height > 0 {
        constraints.push(Constraint::Length(transcript_height));
    }
    constraints.push(Constraint::Length(prompt_height));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    let mut index = 0;
    render_lines(frame, chunks[index], view_lines);
    index += 1;
    index += 1;

    if throttle_height > 0 {
        render_throttle_banner(frame, chunks[index], app);
        index += 1;
    }
    if status_height > 0 {
        render_status_footer(frame, chunks[index], app);
        index += 1;
    }
    if keybind_height > 0 {
        render_keybind_footer(frame, chunks[index], app);
        index += 1;
    }
    if budget_height > 0 {
        render_cost_cap_halt(frame, chunks[index], app);
        index += 1;
    }
    if plan_height > 0 {
        render_plan_card(frame, chunks[index], app);
        index += 1;
    }
    if threat_patch_height > 0 {
        render_threat_patch_card(frame, chunks[index], app);
        index += 1;
    }
    if confirm_height > 0 {
        render_confirm_card(frame, chunks[index], app);
        index += 1;
    }
    if transcript_height > 0 {
        render_transcript(frame, chunks[index], app);
        index += 1;
    }
    render_prompt(frame, chunks[index], app);
}

#[cfg(test)]
mod tests;
