use super::*;
use crate::ui_view_models::{
    knowledge_base_model, KnowledgeBaseArtifactRow, KnowledgeBaseAttachmentRow, KnowledgeBaseModel,
    KnowledgeBaseSummaryRow,
};

pub(crate) fn knowledge_base_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = knowledge_base_model(app);

    lines.push(blank());
    lines.push(divider(model.title, area.width));
    for row in &model.summary_rows {
        lines.push(summary_row(row));
    }
    lines.push(blank());

    append_known_artifacts(&mut lines, &model, area);
    append_attached_records(&mut lines, &model, area);

    lines.push(blank());
    lines.push(command_list_line(&model.commands, area.width as usize));
    lines
}

fn summary_row(row: &KnowledgeBaseSummaryRow) -> Line<'static> {
    detail(&row.cells[0], &row.cells[1])
}

fn append_known_artifacts(lines: &mut Vec<Line<'static>>, model: &KnowledgeBaseModel, area: Rect) {
    lines.push(divider("KNOWN ARTIFACTS", area.width));
    if model.artifact_rows.is_empty() {
        lines.push(muted("No artifacts indexed for this module yet."));
        return;
    }
    lines.push(table_header(
        &["state", "path", "description"],
        &kb_artifact_widths(area.width),
    ));
    let widths = kb_artifact_widths(area.width);
    for artifact in &model.artifact_rows {
        lines.push(artifact_row(artifact, &widths));
    }
}

fn artifact_row(artifact: &KnowledgeBaseArtifactRow, widths: &[usize]) -> Line<'static> {
    let [state, path, description] = &artifact.cells;
    table_row(
        &[
            state,
            &fit(path, widths.get(1).copied().unwrap_or(24)),
            &fit(description, widths.get(2).copied().unwrap_or(20)),
        ],
        widths,
    )
}

fn append_attached_records(lines: &mut Vec<Line<'static>>, model: &KnowledgeBaseModel, area: Rect) {
    lines.push(blank());
    if model.attachment_rows.is_empty() {
        lines.push(divider("ATTACHED · empty", area.width));
        lines.extend(empty_state_panel(
            "no attachments yet",
            &[
                "kuzushi indexes attachments under .kuzushi/v2/artifact-kb.sqlite3.",
                "this module has no path or URL attachments bound.",
            ],
            &[
                (
                    "attach <path>",
                    "add a workspace-relative file or directory",
                ),
                ("attach https://...", "add a URL · metadata-only by default"),
                (
                    "kb pull kev",
                    "preload KEV / NVD / CWE catalogs (network required)",
                ),
            ],
        ));
        return;
    }
    lines.push(divider("ATTACHED", area.width));
    lines.push(table_header(
        &["id", "kind", "source", "status"],
        &kb_attachment_widths(area.width),
    ));
    let widths = kb_attachment_widths(area.width);
    for record in &model.attachment_rows {
        lines.push(attachment_row(record, &widths));
    }
}

fn attachment_row(record: &KnowledgeBaseAttachmentRow, widths: &[usize]) -> Line<'static> {
    let [id, kind, source, status] = &record.cells;
    table_row(
        &[
            id,
            kind,
            &fit(source, widths.get(2).copied().unwrap_or(22)),
            &fit(status, widths.get(3).copied().unwrap_or(18)),
        ],
        widths,
    )
}

pub(crate) fn kb_artifact_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let state = 7;
    let path = if total < 88 { 30 } else { 42 };
    let gaps = 4;
    let description = total.saturating_sub(state + path + gaps).max(16);
    vec![state, path, description]
}
