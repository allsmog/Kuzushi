use super::*;
pub(in crate::renderer) use super::*;

/// Chat bubble tag header matching `design/mockups/agent-chat.jsx::bubble`:
///
///   ` <tag> ──────────────────────────...──`
///
/// `tag_style` carries the role tint (`c-accent` for the operator side,
/// `c-success` for the agent side, `c-danger` for errors).
pub(in crate::renderer) use context_lines::*;
pub(in crate::renderer) use kb_attachment_widths::*;
pub(in crate::renderer) use knowledge_base_lines::*;
pub(in crate::renderer) use project_model_lines::*;
pub(in crate::renderer) use severity_rollup_bar::*;
pub(in crate::renderer) use strategy_queue_lines::*;
pub(in crate::renderer) use workspace_lines::*;
mod context_lines;
mod kb_attachment_widths;
mod knowledge_base_lines;
mod project_model_lines;
mod severity_rollup_bar;
mod strategy_queue_lines;
pub(crate) use strategy_queue_lines::{strategy_queue_max_scroll, strategy_queue_page_rows};
mod workspace_lines;
pub(crate) use context_lines::{context_lines, context_page_rows};
pub(crate) use kb_attachment_widths::kb_attachment_widths;
pub(crate) use knowledge_base_lines::kb_artifact_widths;
pub(crate) use knowledge_base_lines::knowledge_base_lines;
pub(crate) use project_model_lines::project_model_lines;
pub(crate) use severity_rollup_bar::severity_rollup_bar;
pub(crate) use strategy_queue_lines::strategy_queue_lines;
pub(crate) use workspace_lines::workspace_lines;
