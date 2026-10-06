//! Read-only context catalog and document projection. No active-model mutation.
use crate::app::{ShellApp, ThreatModelStoreState};
use crate::renderer::shared::text::wrap_text;
use crate::ViewDataState;
use kuzushi_core::{ThreatModelManifest, ThreatModelRef};
use ratatui::layout::Rect;
use serde_json::Value;
use std::time::{Duration, SystemTime};

pub(crate) mod diagram;

pub(crate) fn context_diagram_model(
    document: &Value,
    target: Option<&std::path::Path>,
) -> super::DfdModel {
    super::viz_data::dfd_model_from_doc(Some(document), target)
}

pub(crate) fn context_layout(
    area: Rect,
    row_count: usize,
) -> super::study_config::StudyConfigLayout {
    let mut layout = super::study_config::study_config_layout(area);
    if layout.list.x == layout.detail.x {
        let unused = layout
            .list
            .height
            .saturating_sub(row_count.min(u16::MAX as usize) as u16);
        layout.list.height -= unused;
        let reclaimed = layout.detail.y.saturating_sub(layout.list.bottom());
        layout.detail.y = layout.list.bottom();
        layout.detail.height += reclaimed;
    }
    layout
}

pub(crate) struct ContextCatalog {
    pub(crate) rows: Vec<ContextRow>,
    pub(crate) status: String,
}

pub(crate) struct ContextRow {
    pub(crate) reference: Option<ThreatModelRef>,
    pub(crate) label: String,
    pub(crate) details: Vec<String>,
}

pub(crate) fn context_catalog(app: &ShellApp) -> ContextCatalog {
    let mut catalog = ContextCatalog {
        rows: vec![omission_row()],
        status: String::new(),
    };
    let state = app
        .workbench_cache()
        .borrow()
        .cached_threat_model_store(app.target());
    match state {
        ViewDataState::Ready(ThreatModelStoreState::Ready { manifest, .. }) => {
            append_revisions(&mut catalog, &manifest)
        }
        ViewDataState::Ready(ThreatModelStoreState::Invalid(error)) => {
            catalog.status = format!("Context catalog unavailable: {error}")
        }
        ViewDataState::Ready(ThreatModelStoreState::Legacy) => catalog.status =
            "No immutable revisions. Build or import context from Map, then return to this study."
                .into(),
        _ => catalog.status = "Loading context revisions…".into(),
    }
    catalog
}

fn omission_row() -> ContextRow {
    ContextRow {
        reference: None, label: "Omit threat-model context".into(),
        details: vec!["Discovery will receive no threat-model document. This is an explicit context experiment, not a claim that the repository has no threats.".into(), "a uses this omission for the study. No scan starts.".into()],
    }
}

fn append_revisions(catalog: &mut ContextCatalog, manifest: &ThreatModelManifest) {
    for model in &manifest.models {
        for (index, revision) in model.revisions.iter().enumerate().rev() {
            let scope = revision.scope.as_ref().unwrap_or(&model.scope);
            catalog.rows.push(ContextRow {
                reference: Some(ThreatModelRef {
                    model_id: model.model_id.clone(),
                    revision_id: revision.revision_id.clone(),
                    sha256: revision.sha256.clone(),
                }),
                label: format!("{} · revision {}", model.label, index + 1),
                details: vec![
                    format!("{} · {}", model.label, model.methodology),
                    format!("Scope: {}", scope.rel_path.display()),
                    format!("Recorded source revision: {}", scope.target_revision),
                    format!(
                        "Grounding check: {}",
                        revision
                            .verification
                            .as_ref()
                            .map_or("unverified", |check| check.verdict.as_str())
                    ),
                    format!("Saved: {}", context_age(&revision.created_at)),
                    format!("Context digest: {}", revision.sha256),
                ],
            });
        }
    }
    catalog.status = format!(
        "{} immutable revisions. Selection applies only to this study.",
        catalog.rows.len() - 1
    );
}

fn context_age(recorded: &str) -> String {
    let seconds = recorded
        .parse::<u64>()
        .ok()
        .or_else(|| kuzushi_core::session_transcript::unix_seconds_from_timestamp(recorded));
    seconds
        .and_then(|seconds| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
        .and_then(|then| super::format_relative_age(SystemTime::now(), then))
        .unwrap_or_else(|| format!("unavailable ({recorded})"))
}

pub(crate) fn context_detail_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let Some(picker) = app.study_context_picker() else {
        return Vec::new();
    };
    let catalog = context_catalog(app);
    let mut text = vec![catalog.status, String::new()];
    if let Some(notice) =
        super::study_config::study_projection(app).and_then(|config| config.notice)
    {
        text.extend([notice, String::new()]);
    }
    let selected = catalog
        .rows
        .iter()
        .find(|row| row.reference == picker.selected);
    append_selected_context(&mut text, selected, picker);
    text.into_iter()
        .flat_map(|line| context_wrap(&line, width.max(1)))
        .collect()
}

fn append_selected_context(
    text: &mut Vec<String>,
    selected: Option<&ContextRow>,
    picker: &crate::app::StudyContextPicker,
) {
    match selected {
        Some(row) => text.extend(row.details.iter().take(4).cloned()),
        None => text.push("The selected revision is unavailable in this catalog. It cannot be substituted with another revision.".into()),
    }
    text.extend(preview_lines(picker));
    if let Some(row) = selected {
        text.extend(row.details.iter().skip(4).cloned());
    }
    if picker.preview.is_some() {
        text.push(
            "a uses this exact revision. A new study plan must be approved before scanning.".into(),
        );
        text.push(
            "m reviews its producing run as Map for separate acceptance. No model request is made."
                .into(),
        );
    }
}

pub(super) fn context_wrap(line: &str, width: usize) -> Vec<String> {
    let indent = line
        .bytes()
        .take_while(|byte| *byte == b' ')
        .count()
        .min(width / 2);
    let prefix = " ".repeat(indent);
    wrap_text(line.trim_start(), width.saturating_sub(indent).max(1))
        .into_iter()
        .map(|line| format!("{prefix}{line}"))
        .collect()
}

fn preview_lines(picker: &crate::app::StudyContextPicker) -> Vec<String> {
    if picker.selected.is_none() {
        return Vec::new();
    }
    let Some(preview) = &picker.preview else {
        return vec![String::new(), "Enter inspects this exact revision before it can be used. Reading makes no model requests.".into(), "Historical context may not cover the current source. Review its assumptions and boundaries.".into()];
    };
    if picker.raw {
        let mut lines = vec!["Complete selected context document:".into()];
        lines.extend(preview.raw.clone());
        return lines;
    }
    let mut lines = vec![
        String::new(),
        "CONTEXT SUMMARY · v diagram · Tab complete document".into(),
    ];
    if let Some(notice) = preview.dfd.evidence_notice() {
        lines.push(notice.into());
    }
    lines.extend(context_summary(&preview.document));
    lines
}

fn context_summary(document: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    for key in ["title", "systemContext", "description", "context"] {
        if let Some(value) = document.get(key).and_then(Value::as_str) {
            lines.push(value.into());
        }
    }
    for (label, pointer) in [
        ("Components", "/dfd/nodes"),
        ("Data flows", "/dfd/flows"),
        ("Trust boundaries", "/dfd/trustBoundaries"),
        ("Threats", "/threats"),
        ("Open questions", "/openQuestions"),
    ] {
        lines.extend(context_section(label, document.pointer(pointer)));
    }
    lines
}

fn context_section(label: &str, value: Option<&Value>) -> Vec<String> {
    let rows = value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut lines = vec![format!("{label}: {}", rows.len())];
    lines.extend(rows.iter().map(|row| format!("  {}", context_item(row))));
    lines
}

fn context_item(value: &Value) -> String {
    if let Some(text) = value.as_str() {
        return text.into();
    }
    let title = ["title", "name", "question", "id"]
        .iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str));
    let description = value.get("description").and_then(Value::as_str);
    [title, description]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" — ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn study_context_layout_returns_unused_list_space_to_the_document() {
        let layout = context_layout(Rect::new(0, 0, 80, 24), 3);
        assert_eq!(layout.list.height, 3);
        assert!(layout.detail.height >= 15);
        assert!(layout.detail.bottom() <= layout.controls.y);
    }

    #[test]
    fn study_context_document_wrapping_retains_indentation_and_content() {
        let lines = context_wrap("    \"question\": \"Which callers are trusted?\"", 30);
        assert!(lines.len() > 1);
        assert!(lines
            .iter()
            .all(|line| line.starts_with("    ") && line.len() <= 30));
        assert_eq!(
            lines
                .iter()
                .map(|line| line.trim())
                .collect::<Vec<_>>()
                .join(" "),
            "\"question\": \"Which callers are trusted?\""
        );
    }

    #[test]
    fn study_context_age_discloses_invalid_values() {
        assert!(context_age("0").contains("ago"));
        assert_eq!(context_age("unknown"), "unavailable (unknown)");
    }
}
