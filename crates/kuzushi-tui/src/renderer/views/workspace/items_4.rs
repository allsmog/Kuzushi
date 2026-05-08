use super::*;

pub(crate) fn knowledge_base_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
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

    lines.push(blank());
    lines.push(divider("KB ATTACHMENTS", area.width));
    lines.push(detail("module", module_id));
    lines.push(detail("store", &store));
    lines.push(detail(
        "supported",
        &SUPPORTED_ATTACHMENT_MODULES.join(", "),
    ));
    lines.push(blank());

    lines.push(divider("KNOWN ARTIFACTS", area.width));
    if app.kb_view.artifacts.is_empty() {
        lines.push(muted("No known Rust artifacts for this module."));
    } else {
        lines.push(table_header(
            &["state", "path", "description"],
            &kb_artifact_widths(area.width),
        ));
        let widths = kb_artifact_widths(area.width);
        for artifact in &app.kb_view.artifacts {
            lines.push(table_row(
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

    lines.push(blank());
    if attachments.is_empty() {
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
                ("kb pull kev", "preload the KEV / NVD / CWE catalogs"),
            ],
        ));
    } else {
        lines.push(divider("ATTACHED", area.width));
        lines.push(table_header(
            &["id", "kind", "source", "status"],
            &kb_attachment_widths(area.width),
        ));
        let widths = kb_attachment_widths(area.width);
        for record in attachments {
            let kind = match &record.kind {
                AttachmentKind::Path => "path",
                AttachmentKind::Url => "url",
            };
            lines.push(table_row(
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
    lines.push(blank());
    lines.push(command_list_line(
        &[
            "kb [module]",
            "attach <path-or-url>",
            "detach <id>",
            "reparse <id>",
        ],
        area.width as usize,
    ));
    lines
}

pub(crate) fn kb_artifact_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let state = 7;
    let path = if total < 88 { 30 } else { 42 };
    let gaps = 4;
    let description = total.saturating_sub(state + path + gaps).max(16);
    vec![state, path, description]
}
