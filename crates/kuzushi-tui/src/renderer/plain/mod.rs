use super::*;
pub(in crate::renderer) use super::*;

use self::{
    compact_target_path, findings_count_summary, fit, format_json_value, help_category_blurb,
    join_or_dash, kb_artifact_widths, kb_attachment_widths, model_auth_status, option_alias_label,
    option_description, option_table_widths, option_type_label, option_visible,
    options_filter_label, routing_mode_segment, sast_task_table_widths, shell_view_lines,
    table_text, wrap_text,
};
use crate::app::{LogLine, ShellApp, ShellView};
use crate::commands::{
    shell_command_specs, shell_help_examples, ShellCommandCategory, ShellCommandSpec,
};
pub(in crate::renderer) use finalize_width_safe_plain_lines::*;
use kuzushi_core::{AttachmentKind, SUPPORTED_ATTACHMENT_MODULES};
pub(in crate::renderer) use plain_config_lines::*;
pub(in crate::renderer) use plain_context_lines::*;
pub(in crate::renderer) use plain_knowledge_base_lines::*;
pub(in crate::renderer) use plain_options_lines::*;
pub(in crate::renderer) use plain_sast_tasks_lines::*;
use ratatui::layout::Rect;
use ratatui::prelude::Line;
pub(in crate::renderer) use render_plain_app::*;
mod finalize_width_safe_plain_lines;
mod plain_config_lines;
mod plain_context_lines;
mod plain_knowledge_base_lines;
mod plain_options_lines;
mod plain_sast_tasks_lines;
mod render_plain_app;
pub use render_plain_app::{render_plain_app, render_plain_command_result};
