use super::*;
use crate::app::{StudyContextPicker, StudyContextTextView};

pub(super) fn picker_lines(app: &ShellApp, picker: &StudyContextPicker) -> Vec<String> {
    if picker.text_view == StudyContextTextView::Scanner {
        return scanner::picker_lines(picker);
    }
    let catalog = context_catalog(app);
    let selected = catalog
        .rows
        .iter()
        .find(|row| row.reference == picker.selected);
    if picker.preview.is_some() {
        return inspected_lines(app, picker, &catalog, selected);
    }
    let mut lines = Vec::new();
    append_notice(&mut lines, app);
    lines.extend(selection_lines(app, picker, &catalog, selected));
    if picker.selected.is_some() {
        lines.extend([String::new(), "Enter inspects this exact revision before it can be used. Reading makes no model requests.".into(), "Historical context may not cover the current source. Review its assumptions and boundaries.".into()]);
    }
    lines
}

fn inspected_lines(
    app: &ShellApp,
    picker: &StudyContextPicker,
    catalog: &ContextCatalog,
    selected: Option<&ContextRow>,
) -> Vec<String> {
    let Some(preview) = picker.preview.as_ref() else {
        return Vec::new();
    };
    let mut lines = vec![source_summary(picker).into()];
    append_notice(&mut lines, app);
    if !preview.lesson_usable {
        lines.push("Lesson context needs review before use.".into());
    }
    lines.extend(preview_content(picker));
    lines.extend([String::new(), "CONTEXT DETAILS AND LIMITS".into()]);
    lines.extend(selection_lines(app, picker, catalog, selected));
    lines.push(preview.source_state.clone());
    append_inspected_context_actions(&mut lines, picker);
    lines
}

fn source_summary(picker: &StudyContextPicker) -> &'static str {
    match picker
        .preview
        .as_ref()
        .and_then(|preview| preview.source_status.as_deref())
    {
        Some("matches") => "Source matched at inspection.",
        Some("drifted") => "Earlier source; read only. Replan.",
        _ => "Source unchecked; inspect details.",
    }
}

fn preview_content(picker: &StudyContextPicker) -> Vec<String> {
    let Some(preview) = picker.preview.as_ref() else {
        return Vec::new();
    };
    if picker.text_view == StudyContextTextView::Document {
        let mut lines = super::super::context_goal::context_goal_lines(&preview.goal_state);
        lines.push("Complete selected context document:".into());
        lines.extend(preview.raw.clone());
        return lines;
    }
    let mut lines = Vec::new();
    if let Some(notice) = preview.dfd.evidence_notice() {
        lines.push(notice.into());
    }
    lines.extend(super::super::context_goal::context_goal_lines(
        &preview.goal_state,
    ));
    lines.extend(context_summary(&preview.document));
    lines
}

fn selection_lines(
    app: &ShellApp,
    picker: &StudyContextPicker,
    catalog: &ContextCatalog,
    selected: Option<&ContextRow>,
) -> Vec<String> {
    let mut lines = context_binding_lines(app, picker);
    lines.extend([catalog.status.clone(), String::new()]);
    match selected {
        Some(row) => lines.extend(row.details.clone()),
        None => {
            lines.push(missing_catalog_membership(catalog.membership_known));
            if let Some(reference) = picker.selected.as_ref() {
                lines.extend([
                    format!("Context revision: {}", reference.revision_id),
                    format!("Context lineage: {}", reference.model_id),
                    format!("Context digest: {}", reference.sha256),
                ]);
            }
        }
    }
    lines
}

fn append_notice(lines: &mut Vec<String>, app: &ShellApp) {
    if let Some(notice) =
        super::super::study_config::study_projection(app).and_then(|config| config.notice)
    {
        lines.push(notice);
    }
}
