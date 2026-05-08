pub(in crate::renderer) use super::{
    compact_target_path, findings_count_summary, fit, format_json_value, help_category_blurb,
    join_or_dash, kb_artifact_widths, kb_attachment_widths, model_auth_status, option_description,
    option_table_widths, option_type_label, option_visible, options_filter_label,
    routing_mode_segment, sast_task_table_widths, shell_view_lines, table_text, wrap_text,
};
pub(in crate::renderer) use crate::app::{LogLine, ShellApp, ShellView};
pub(in crate::renderer) use crate::commands::{
    shell_command_specs, shell_help_examples, ShellCommandCategory, ShellCommandSpec,
};
pub(in crate::renderer) use kuzushi_core::{AttachmentKind, SUPPORTED_ATTACHMENT_MODULES};
pub(in crate::renderer) use ratatui::layout::Rect;
pub(in crate::renderer) use ratatui::prelude::Line;
