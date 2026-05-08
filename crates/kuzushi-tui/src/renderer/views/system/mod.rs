pub(in crate::renderer) use super::prelude::*;
pub(in crate::renderer) use super::*;

/// Build the providers table for `auth_lines`.  Keeps the data source
/// honest: `KUZUSHI_API_KEY` / `ANTHROPIC_API_KEY` for env-key auth,
/// `oauth_provider_status` for OAuth.

/// `/patch <alias>` view — RATIONALE / DIFF / TESTS / GUARDRAIL
/// matching `design/mockups/patch.jsx`.  Pulls from
/// `app.pending_patch` when the alias matches; otherwise renders an
/// empty state advising how to stage a patch.

/// Render a single 30-cell budget bar matching
/// `design/mockups/cost.jsx::bar`.  Bar is severity-tinted by spend
/// percentage (success < 85% < warn < 100% < danger).
mod siblings;
pub(crate) use siblings::*;
mod config_lines;
mod items_2;
mod items_3;
mod items_4;
mod items_5;
pub(crate) use config_lines::config_lines;
pub(crate) use items_3::auth_lines;
pub(crate) use items_3::AuthProviderRow;
pub(crate) use items_3::AuthProviderState;
pub(crate) use items_4::auth_provider_line;
pub(crate) use items_4::auth_provider_rows;
pub(crate) use items_5::cost_budget_bar;
pub(crate) use items_5::cost_lines;
