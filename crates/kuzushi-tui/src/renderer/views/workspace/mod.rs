pub(in crate::renderer) use super::prelude::*;
pub(in crate::renderer) use super::*;

/// Chat bubble tag header matching `design/mockups/agent-chat.jsx::bubble`:
///
///   ` <tag> ──────────────────────────...──`
///
/// `tag_style` carries the role tint (`c-accent` for the operator side,
/// `c-success` for the agent side, `c-danger` for errors).
mod siblings;
pub(crate) use siblings::*;
mod context_lines;
mod items_4;
mod kb_attachment_widths;
mod severity_rollup_bar;
mod workspace_lines;
pub(crate) use context_lines::context_lines;
pub(crate) use items_4::kb_artifact_widths;
pub(crate) use items_4::knowledge_base_lines;
pub(crate) use kb_attachment_widths::kb_attachment_widths;
pub(crate) use severity_rollup_bar::severity_rollup_bar;
pub(crate) use workspace_lines::workspace_lines;
