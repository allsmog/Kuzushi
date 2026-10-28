//! Full evidence text and layout for an authenticated study context preview.
use super::*;
use crate::ui_view_models::{
    dfd_security_items_for_selection, dfd_selected_item, DfdLinkState, DfdModel, DfdSelected,
};
use ratatui::text::Line;

pub(crate) fn diagram_body(area: Rect) -> Rect {
    Rect::new(
        area.x + 1,
        area.y + 3,
        area.width.saturating_sub(2),
        area.height.saturating_sub(6),
    )
}

pub(crate) fn diagram_identity(app: &ShellApp) -> String {
    let selected = app
        .study_context_picker()
        .and_then(|picker| picker.selected.as_ref());
    context_catalog(app)
        .rows
        .into_iter()
        .find(|row| row.reference.as_ref() == selected)
        .map(|row| row.label)
        .unwrap_or_else(|| "Selected revision unavailable".into())
}

pub(crate) fn diagram_status(app: &ShellApp) -> String {
    if let Some(notice) = diagram_notice(app) {
        return notice.into();
    }
    let selected = app
        .study_context_picker()
        .and_then(|picker| picker.selected.as_ref());
    context_catalog(app)
        .rows
        .into_iter()
        .find(|row| row.reference.as_ref() == selected)
        .and_then(|row| row.details.get(3).cloned())
        .unwrap_or_else(|| "Grounding: unavailable".into())
}

fn diagram_notice(app: &ShellApp) -> Option<&str> {
    app.study_context_picker()?
        .diagram
        .as_ref()?
        .notice
        .as_deref()
}

pub(crate) fn diagram_detail_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let Some(picker) = app.study_context_picker() else {
        return Vec::new();
    };
    let Some(preview) = &picker.preview else {
        return vec!["Inspect the selected revision first.".into()];
    };
    let selection = picker
        .diagram
        .as_ref()
        .map_or(0, |diagram| diagram.selection);
    let mut lines = selected_element_lines(&preview.dfd, selection);
    if let Some(notice) = diagram_notice(app) {
        lines.splice(0..0, [notice.into(), String::new()]);
    }
    lines.extend(linked_evidence_lines(&preview.dfd, selection));
    wrap_diagram_lines(lines, width)
}

fn wrap_diagram_lines(lines: Vec<String>, width: usize) -> Vec<String> {
    crate::renderer::shared::text::wrap_document_lines(
        lines.into_iter().map(Line::raw).collect(),
        width.clamp(1, u16::MAX as usize) as u16,
    )
    .into_iter()
    .map(|line| line.to_string())
    .collect()
}

fn selected_element_lines(model: &DfdModel, selection: usize) -> Vec<String> {
    match dfd_selected_item(model, selection) {
        Some(DfdSelected::Node(node)) => vec![
            format!("COMPONENT · {}", node.name),
            format!("Trust zone: {}", node.zone),
            node.description
                .clone()
                .unwrap_or_else(|| "Description not recorded.".into()),
            format!(
                "Purpose: {}",
                node.purpose.as_deref().unwrap_or("not recorded")
            ),
            format!("Element: {}", node.key),
        ],
        Some(DfdSelected::Flow(flow)) => vec![
            format!("DATA FLOW · {} → {}", flow.from, flow.to),
            flow.label.clone(),
            format!("Crosses trust boundary: {}", flow.crosses),
            format!("Boundaries: {}", flow.boundary_ids.join(", ")),
            format!("Element: {}", flow.key),
        ],
        Some(DfdSelected::Boundary(boundary)) => vec![
            format!("TRUST BOUNDARY · {}", boundary.name),
            format!("{} → {}", boundary.outer_zone, boundary.inner_zone),
            format!("Crossing flows: {}", boundary.crossing_flow_ids.join(", ")),
            format!("Element: {}", boundary.key),
        ],
        None => vec!["No diagram elements recorded in this revision.".into()],
    }
}

fn linked_evidence_lines(model: &DfdModel, selection: usize) -> Vec<String> {
    if model.link_state != DfdLinkState::Complete {
        return vec![String::new(), "Context links are unverified. No linked evidence is inferred; inspect the complete document for its recorded claims.".into()];
    }
    let items = dfd_security_items_for_selection(model, selection);
    let mut lines = vec![
        String::new(),
        format!("LINKED CONTEXT · {} recorded items", items.len()),
    ];
    for item in items {
        let evidence = item.evidence_label();
        lines.extend([
            String::new(),
            item.label.clone(),
            item.detail.clone(),
            format!("Evidence: {evidence}"),
        ]);
        lines.extend(
            item.evidence_paths
                .iter()
                .filter(|path| **path != item.evidence)
                .map(|path| format!("Source: {}", serde_json::json!(path))),
        );
    }
    lines
}

/// Plain output is exhaustive; selection never hides the remaining topology.
pub(crate) fn diagram_plain_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let Some(preview) = app
        .study_context_picker()
        .and_then(|picker| picker.preview.as_ref())
    else {
        return Vec::new();
    };
    let model = &preview.dfd;
    let mut lines = vec![
        "CONTEXT DATA FLOW".into(),
        diagram_identity(app),
        diagram_status(app),
    ];
    if let Some(reference) = app
        .study_context_picker()
        .and_then(|picker| picker.selected.as_ref())
    {
        lines.extend([
            format!(
                "Context: {} · {}",
                reference.model_id, reference.revision_id
            ),
            format!("Context digest: {}", reference.sha256),
        ]);
    }
    if let Some(hint) = &model.empty_hint {
        lines.push(hint.clone());
    }
    for selection in 0..crate::ui_view_models::dfd_selectable_count(model) {
        lines.push(String::new());
        lines.extend(selected_element_lines(model, selection));
        lines.extend(linked_evidence_lines(model, selection));
    }
    wrap_diagram_lines(lines, width)
}

#[cfg(test)]
mod tests;
