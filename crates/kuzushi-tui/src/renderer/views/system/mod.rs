use super::*;
pub(in crate::renderer) use super::*;

/// Build the providers table for `auth_lines`.  Keeps the data source
/// honest: `KUZUSHI_API_KEY` / `ANTHROPIC_API_KEY` for env-key auth,
/// `oauth_provider_status` for OAuth.

/// `/patch <alias>` view — RATIONALE / DIFF / TESTS / GUARDRAIL
/// matching `design/mockups/patch.jsx`.  Pulls from
/// engagement pending patch state when the alias matches; otherwise renders an
/// empty state advising how to stage a patch.

/// Render a single 30-cell budget bar matching
/// `design/mockups/cost.jsx::bar`.  Bar is severity-tinted by spend
/// percentage (success < 85% < warn < 100% < danger).
pub(in crate::renderer) use auth_lines::*;
pub(in crate::renderer) use auth_provider_rows::*;
pub(in crate::renderer) use command_palette_lines::*;
pub(in crate::renderer) use config_lines::*;
pub(in crate::renderer) use cost_lines::*;
pub(in crate::renderer) use health_lines::*;
pub(in crate::renderer) use interruption_lines::*;
pub(in crate::renderer) use overlay_lines::*;
pub(in crate::renderer) use tools_lines::*;
mod auth_lines;
mod auth_provider_rows;
mod command_palette_lines;
mod config_lines;
mod cost_lines;
mod health_lines;
mod interruption_content;
mod interruption_lines;
mod overlay_lines;
mod tools_lines;
pub(crate) use auth_lines::auth_lines;
pub(crate) use auth_provider_rows::{auth_provider_line, auth_provider_lines};
pub(crate) use command_palette_lines::command_palette_lines;
pub(crate) use config_lines::config_lines;
pub(crate) use cost_lines::cost_budget_bar;
pub(crate) use cost_lines::cost_lines;
pub(crate) use health_lines::health_lines;
pub(crate) use interruption_lines::interruption_lines;
pub(crate) use overlay_lines::{
    boot_splash_lines, confirm_dialog_lines, keymap_lines, quit_confirm_lines, theme_picker_lines,
    update_available_lines,
};
pub(crate) use tools_lines::tools_lines;
