use super::*;
pub(crate) use super::*;

use self::{ShellApp, SCENE_FRAME, SPINNER_FRAME};
use crate::renderer::{render_app, render_plain_app, render_plain_command_result};
use anyhow::{Context, Result};
use crossterm::cursor::MoveTo;
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen,
};
use kuzushi_core::{ModuleRegistry, V2Config, WorkspaceTarget};
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::Terminal;
pub(crate) use refresh_terminal_redraw_state::*;
pub(crate) use render_plain_scripted_session::*;
pub(crate) use run_shell::*;
use std::env;
use std::io::{self, IsTerminal, Read, Stdout};
use std::time::Duration;
mod refresh_terminal_redraw_state;
mod render_plain_scripted_session;
mod run_shell;
mod terminal_loop_event;
#[cfg(test)]
mod tests;
mod workspace_watcher;
pub(super) use render_plain_scripted_session::mouse_capture_setting_enabled;
#[cfg(test)]
pub(super) use render_plain_scripted_session::render_plain_scripted_session;
pub use run_shell::run_shell;
pub use run_shell::run_shell_with_context;
pub use run_shell::run_shell_with_plain;
pub use run_shell::{ShellLaunchContext, ShellTargetSource};
pub(crate) use terminal_loop_event::*;
pub(crate) use workspace_watcher::*;
