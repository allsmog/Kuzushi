use super::*;

pub(crate) fn plain_knowledge_base_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let module_id = app.kb_view.module_id.as_str();
    let attachments = app
        .kb_view
        .attachments
        .iter()
        .filter(|record| record.module_id == module_id)
        .collect::<Vec<_>>();
    let store = app
        .kb_view
        .store_path
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| ".kuzushi/v2/attachments.json".to_string());

    lines.push(String::new());
    lines.push(plain_section_divider("KB ATTACHMENTS", width));
    lines.push(format!("module: {module_id}"));
    lines.push(format!("store: {store}"));
    lines.push(format!(
        "supported: {}",
        SUPPORTED_ATTACHMENT_MODULES.join(", ")
    ));

    lines.push(String::new());
    lines.push(plain_section_divider("KNOWN ARTIFACTS", width));
    if app.kb_view.artifacts.is_empty() {
        lines.push("No known Rust artifacts for this module.".to_string());
    } else {
        let widths = kb_artifact_widths(width.min(u16::MAX as usize) as u16);
        lines.push(table_text(&["state", "path", "description"], &widths));
        for artifact in &app.kb_view.artifacts {
            lines.push(table_text(
                &[
                    if artifact.exists {
                        "present"
                    } else {
                        "missing"
                    },
                    &fit(&artifact.path, widths.get(1).copied().unwrap_or(24)),
                    &fit(&artifact.description, widths.get(2).copied().unwrap_or(20)),
                ],
                &widths,
            ));
        }
    }

    lines.push(String::new());
    lines.push(plain_section_divider("ATTACHED", width));
    if attachments.is_empty() {
        lines.push(
            "No attachments yet. Next: attach <repo-relative-path> or attach <url>".to_string(),
        );
    } else {
        let widths = kb_attachment_widths(width.min(u16::MAX as usize) as u16);
        lines.push(table_text(&["id", "kind", "source", "status"], &widths));
        for record in attachments {
            let kind = match &record.kind {
                AttachmentKind::Path => "path",
                AttachmentKind::Url => "url",
            };
            lines.push(table_text(
                &[
                    &record.id,
                    kind,
                    &fit(&record.source, widths.get(2).copied().unwrap_or(22)),
                    &fit(&record.status, widths.get(3).copied().unwrap_or(18)),
                ],
                &widths,
            ));
        }
    }
    lines.push(String::new());
    lines.push("Next: kb [module], attach <path-or-url>, detach <id>, reparse <id>".to_string());
    lines
}
