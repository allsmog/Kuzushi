//! Cached immutable history and complete local read projections.
use crate::app::{ContextHistoryRequest, ContextHistoryState, ShellApp, ThreatModelStoreState};
use crate::renderer::shared::text::wrap_text;
use crate::ViewDataState;
use kuzushi_core::{ThreatModelManifest, ThreatModelRef};
use ratatui::layout::{Constraint, Layout, Rect};
use serde_json::Value;

mod document;
pub(crate) use document::history_detail_lines;

pub(crate) struct ContextHistoryLayout {
    pub(crate) header: Rect,
    pub(crate) list: Option<Rect>,
    pub(crate) detail: Rect,
    pub(crate) controls: Rect,
}

pub(crate) fn history_layout(area: Rect, reader: bool) -> ContextHistoryLayout {
    let inner = area.inner(ratatui::layout::Margin::new(2, 1));
    let parts = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(3),
    ])
    .split(inner);
    let (list, detail) = history_panes(parts[1], reader);
    ContextHistoryLayout {
        header: parts[0],
        list,
        detail,
        controls: parts[2],
    }
}

fn history_panes(area: Rect, reader: bool) -> (Option<Rect>, Rect) {
    if reader {
        return (None, area);
    }
    let panes = if area.width >= 96 {
        Layout::horizontal([Constraint::Percentage(38), Constraint::Min(1)])
            .spacing(2)
            .split(area)
    } else {
        let height = (area.height / 3).clamp(1, 6).min(area.height);
        Layout::vertical([Constraint::Length(height), Constraint::Min(1)])
            .spacing(1)
            .split(area)
    };
    (Some(panes[0]), panes[1])
}

pub(crate) struct ContextHistoryRow {
    pub(crate) reference: ThreatModelRef,
    pub(crate) label: String,
    pub(crate) details: Vec<String>,
    pub(crate) active: bool,
}

pub(crate) struct ContextHistoryCatalog {
    pub(crate) rows: Vec<ContextHistoryRow>,
    pub(crate) status: String,
}

impl ContextHistoryCatalog {
    pub(crate) fn selected_index(&self, state: Option<&ContextHistoryState>) -> Option<usize> {
        if let Some(reference) = state.and_then(|state| state.selected.as_ref()) {
            return self.rows.iter().position(|row| &row.reference == reference);
        }
        self.rows
            .iter()
            .position(|row| row.active)
            .or_else(|| (!self.rows.is_empty()).then_some(0))
    }

    pub(crate) fn label(&self, reference: &ThreatModelRef) -> String {
        self.rows
            .iter()
            .find(|row| &row.reference == reference)
            .map(|row| row.label.clone())
            .unwrap_or_else(|| reference.revision_id.to_string())
    }
}

pub(crate) fn history_catalog(app: &ShellApp) -> ContextHistoryCatalog {
    let state = app
        .workbench_cache()
        .borrow()
        .cached_threat_model_store(app.target());
    match state {
        ViewDataState::Ready(ThreatModelStoreState::Ready { manifest, .. }) => {
            catalog_from_manifest(&manifest)
        }
        ViewDataState::Ready(ThreatModelStoreState::Invalid(error)) => {
            empty_catalog(format!("Context history unavailable: {error}"))
        }
        ViewDataState::Ready(ThreatModelStoreState::Legacy) => {
            empty_catalog("No immutable revisions. Build or import context first.".into())
        }
        _ => empty_catalog("Loading saved context history…".into()),
    }
}

fn empty_catalog(status: String) -> ContextHistoryCatalog {
    ContextHistoryCatalog {
        rows: Vec::new(),
        status,
    }
}

fn catalog_from_manifest(manifest: &ThreatModelManifest) -> ContextHistoryCatalog {
    let mut rows = Vec::new();
    for model in &manifest.models {
        for (index, revision) in model.revisions.iter().enumerate().rev() {
            rows.push(history_row(
                model,
                revision,
                index,
                manifest.active.as_ref(),
            ));
        }
    }
    ContextHistoryCatalog {
        status: format!(
            "{} lineages · {} saved revisions",
            manifest.models.len(),
            rows.len()
        ),
        rows,
    }
}

fn history_row(
    model: &kuzushi_core::ThreatModelMetadata,
    revision: &kuzushi_core::ThreatModelRevisionMetadata,
    index: usize,
    active: Option<&ThreatModelRef>,
) -> ContextHistoryRow {
    let reference = ThreatModelRef {
        model_id: model.model_id.clone(),
        revision_id: revision.revision_id.clone(),
        sha256: revision.sha256.clone(),
    };
    let scope = revision.scope.as_ref().unwrap_or(&model.scope);
    ContextHistoryRow {
        active: active == Some(&reference),
        reference,
        label: format!("{} · revision {}", model.label, index + 1),
        details: vec![
            format!("{} · {}", model.label, model.methodology),
            format!("Revision: {}", revision.revision_id),
            format!("Saved: {} · {:?}", revision.created_at, revision.source),
            format!("Scope: {}", scope.rel_path.display()),
            format!("Recorded source revision: {}", scope.target_revision),
            format!("Context digest: {}", revision.sha256),
            format!(
                "Recorded verification: {}",
                super::threat_model::verification_label(revision)
            ),
        ],
    }
}

pub(crate) fn history_controls(request: Option<&ContextHistoryRequest>) -> [&'static str; 3] {
    match request {
        Some(ContextHistoryRequest::Read(_)) => [
            "↑↓ / PgUp/Dn read · Home/End",
            "Tab view · Enter retry · Esc back",
            "Local read · no model request",
        ],
        Some(ContextHistoryRequest::Compare { .. }) => [
            "↑↓ / PgUp/Dn read · Home/End",
            "Enter retry on error · Esc back",
            "Local comparison · no model request",
        ],
        None => [
            "↑↓ select · Enter inspect",
            "b baseline · c compare · PgUp/Dn",
            "a activate · r restore · Esc close",
        ],
    }
}

pub(crate) fn history_plain_lines(app: &ShellApp, width: usize) -> Option<Vec<String>> {
    let state = app.context_history()?;
    let catalog = history_catalog(app);
    let mut lines = vec![
        "CONTEXT HISTORY".into(),
        catalog.status.clone(),
        format!("Target: {}", state.target.display()),
    ];
    if let Some(baseline) = &state.baseline {
        lines.push(format!("Baseline: {}", catalog.label(baseline)));
    }
    for row in &catalog.rows {
        lines.push(format!(
            "{}{}",
            row.label,
            if row.active { " · active" } else { "" }
        ));
        lines.extend(row.details.clone());
    }
    lines.extend(history_detail_lines(state, &catalog, width));
    append_plain_document(&mut lines, state, width);
    lines.extend(history_controls(state.request.as_ref()).map(str::to_string));
    Some(lines)
}

fn wrapped(lines: Vec<String>, width: usize) -> Vec<String> {
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

fn append_plain_document(lines: &mut Vec<String>, state: &ContextHistoryState, width: usize) {
    if state.document_raw || !matches!(state.request, Some(ContextHistoryRequest::Read(_))) {
        return;
    }
    let Some(document) = state.data.as_ref().map(|data| &data["document"]) else {
        return;
    };
    lines.extend(wrapped(
        vec![serde_json::to_string_pretty(document).unwrap_or_else(|error| error.to_string())],
        width,
    ));
}

#[cfg(test)]
mod tests;
