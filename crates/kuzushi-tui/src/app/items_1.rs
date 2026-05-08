use super::prelude::*;
use super::*;

#[cfg(test)]
use runtime::{mouse_capture_setting_enabled, render_plain_scripted_session};

#[cfg(test)]
use workers::{parse_plan_json, parse_threat_patch_json};

pub(crate) const CTRL_C_ARM_WINDOW: Duration = Duration::from_secs(2);

pub(crate) const THROTTLE_STALE_AFTER: Duration = Duration::from_secs(30);

pub(crate) const SPINNER_FRAME: Duration = Duration::from_millis(80);

pub(crate) const VIEWPORT_PAGE_LINES: usize = 10;

pub(crate) const FINDINGS_PAGE_ROWS: usize = 10;

#[cfg(test)]
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[cfg(test)]
use state_transitions::{HotkeyTrigger, ViewHotkeyAction};
