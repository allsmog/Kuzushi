use super::*;
use crate::ui_view_models::{
    knowledge_base_model, KnowledgeBaseArtifactRow, KnowledgeBaseAttachmentRow, KnowledgeBaseModel,
};

pub(crate) fn plain_knowledge_base_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = knowledge_base_model(app);

    lines.push(String::new());
    lines.push(plain_section_divider("KB ATTACHMENTS", width));
    lines.push(format!("module: {}", model.module_id_label));
    lines.push(format!("store: {}", model.store_label));
    lines.push(format!("supported: {}", model.supported_label));

    push_plain_artifacts(&mut lines, &model, width);
    push_plain_attachments(&mut lines, &model, width);

    lines.push(String::new());
    lines.push("Next: kb [module], attach <path-or-url>, detach <id>, reparse <id>".to_string());
    lines
}

fn push_plain_artifacts(lines: &mut Vec<String>, model: &KnowledgeBaseModel, width: usize) {
    lines.push(String::new());
    lines.push(plain_section_divider("KNOWN ARTIFACTS", width));
    if model.artifact_rows.is_empty() {
        lines.push("No known Rust artifacts for this module.".to_string());
        return;
    }
    let widths = kb_artifact_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(&["state", "path", "description"], &widths));
    for artifact in &model.artifact_rows {
        lines.push(plain_artifact_row(artifact, &widths));
    }
}

fn plain_artifact_row(artifact: &KnowledgeBaseArtifactRow, widths: &[usize]) -> String {
    table_text(
        &[
            artifact.state,
            &fit(&artifact.path, widths.get(1).copied().unwrap_or(24)),
            &fit(&artifact.description, widths.get(2).copied().unwrap_or(20)),
        ],
        widths,
    )
}

fn push_plain_attachments(lines: &mut Vec<String>, model: &KnowledgeBaseModel, width: usize) {
    lines.push(String::new());
    lines.push(plain_section_divider("ATTACHED", width));
    if model.attachment_rows.is_empty() {
        lines.push(
            "No attachments yet. Next: attach <repo-relative-path> or attach <url>".to_string(),
        );
        return;
    }
    let widths = kb_attachment_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(&["id", "kind", "source", "status"], &widths));
    for record in &model.attachment_rows {
        lines.push(plain_attachment_row(record, &widths));
    }
}

fn plain_attachment_row(record: &KnowledgeBaseAttachmentRow, widths: &[usize]) -> String {
    table_text(
        &[
            &record.id,
            record.kind,
            &fit(&record.source, widths.get(2).copied().unwrap_or(22)),
            &fit(&record.status, widths.get(3).copied().unwrap_or(18)),
        ],
        widths,
    )
}
