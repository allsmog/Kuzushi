use self::{
    ActorDetailFilter, BudgetHalt, Notice, NoticeSeverity, PromptsAction, ShellApp, ShellView,
    ThreatView, ThrottleAdvisory, FINDINGS_PAGE_ROWS, NOTICE_STALE_AFTER, SCENE_FRAME, SCENE_NUDGE,
    SCENE_SPIN_RATE, SPINNER_FRAME, THROTTLE_STALE_AFTER, VIEWPORT_PAGE_LINES,
};
pub(in crate::app) use super::*;
use crate::commands::ShellCommand;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEvent, MouseEventKind};
use std::time::Instant;

#[derive(Default)]
pub(crate) struct InputUpdate {
    pub(crate) handled: bool,
    pub(crate) effects: Vec<ShellEffect>,
}

impl InputUpdate {
    pub(crate) fn handled() -> Self {
        Self {
            handled: true,
            effects: Vec::new(),
        }
    }

    pub(crate) fn ignored() -> Self {
        Self::default()
    }

    pub(crate) fn handled_if(handled: bool) -> Self {
        if handled {
            Self::handled()
        } else {
            Self::ignored()
        }
    }

    pub(crate) fn handled_with_effects(effects: Vec<ShellEffect>) -> Self {
        Self {
            handled: true,
            effects,
        }
    }
}
mod back_navigation;
mod budget_guard;
mod confirmation_keys;
mod control_keys;
mod cursor_and_view_keys;
mod exit_requests;
mod key_dispatch;
mod keybinding_types;
mod operator_question_keys;
mod page_scroll;
mod pending_plan_keys;
mod picker_keys;
mod prereq_prompt_keys;
mod quit_chord;
mod scroll_navigation;
mod text_input;
mod ticking;
mod view_hotkey_actions;
mod view_keybinding_groups;
mod view_keybinding_helpers;
mod view_keybindings;

pub(in crate::app) use keybinding_types::HotkeyTrigger;
pub(in crate::app) use keybinding_types::KeyModifierState;
pub(in crate::app) use keybinding_types::ViewHotkeyAction;
pub(in crate::app) use keybinding_types::ViewKeybinding;
pub(crate) use quit_chord::is_quit_chord;
use view_keybinding_groups::*;
use view_keybinding_helpers::*;
