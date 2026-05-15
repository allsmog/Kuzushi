use super::*;
use crate::ui_view_models::{
    plain_knowledge_base_model, PlainKnowledgeBaseArtifactRow, PlainKnowledgeBaseArtifacts,
    PlainKnowledgeBaseAttachmentRow, PlainKnowledgeBaseAttachments, PlainKnowledgeBaseModel,
};

pub(crate) fn plain_knowledge_base_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = plain_knowledge_base_model(app);

    push_plain_knowledge_base_summary(&mut lines, &model, width);
    push_plain_artifacts(&mut lines, &model.artifact_section, width);
    push_plain_attachments(&mut lines, &model.attachment_section, width);
    lines.push(String::new());
    lines.push(model.next_hint.to_string());
    lines
}

fn push_plain_knowledge_base_summary(
    lines: &mut Vec<String>,
    model: &PlainKnowledgeBaseModel,
    width: usize,
) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.title, width));
    lines.extend(model.summary_rows.iter().cloned());
}

fn push_plain_artifacts(
    lines: &mut Vec<String>,
    section: &PlainKnowledgeBaseArtifacts,
    width: usize,
) {
    lines.push(String::new());
    lines.push(plain_section_divider(section.title, width));
    if let Some(message) = section.empty_message {
        lines.push(message.to_string());
        return;
    }
    let widths = kb_artifact_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(&section.headers, &widths));
    for artifact in &section.rows {
        lines.push(plain_artifact_row(artifact, &widths));
    }
}

fn plain_artifact_row(artifact: &PlainKnowledgeBaseArtifactRow, widths: &[usize]) -> String {
    table_text(
        &[
            artifact.state,
            &fit(&artifact.path, widths.get(1).copied().unwrap_or(24)),
            &fit(&artifact.description, widths.get(2).copied().unwrap_or(20)),
        ],
        widths,
    )
}

fn push_plain_attachments(
    lines: &mut Vec<String>,
    section: &PlainKnowledgeBaseAttachments,
    width: usize,
) {
    lines.push(String::new());
    lines.push(plain_section_divider(section.title, width));
    if let Some(message) = section.empty_message {
        lines.push(message.to_string());
        return;
    }
    let widths = kb_attachment_widths(width.min(u16::MAX as usize) as u16);
    lines.push(table_text(&section.headers, &widths));
    for record in &section.rows {
        lines.push(plain_attachment_row(record, &widths));
    }
}

fn plain_attachment_row(record: &PlainKnowledgeBaseAttachmentRow, widths: &[usize]) -> String {
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
