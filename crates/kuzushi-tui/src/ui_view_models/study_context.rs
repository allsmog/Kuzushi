//! Read-only context catalog and document projection. No active-model mutation.
use crate::app::{ShellApp, ThreatModelStoreState};
use crate::renderer::shared::text::wrap_text;
use crate::ViewDataState;
use kuzushi_core::{ThreatModelManifest, ThreatModelRef};
use ratatui::layout::Rect;
use serde_json::Value;
use std::time::{Duration, SystemTime};

pub(crate) mod diagram;
mod scanner;

pub(crate) fn context_header_title(app: &ShellApp) -> &'static str {
    let picker = app.study_context_picker();
    if picker.is_some_and(|picker| picker.text_view == crate::app::StudyContextTextView::Scanner) {
        return " SCANNER CONTEXT PREVIEW ";
    }
    if picker.is_some_and(|picker| picker.regeneration_entry) {
        return " CHOOSE CONTEXT TO REGENERATE ";
    }
    " CHOOSE STUDY CONTEXT "
}

pub(crate) fn context_text_controls(
    view: crate::app::StudyContextTextView,
    width: u16,
) -> Option<&'static str> {
    if view != crate::app::StudyContextTextView::Scanner {
        return None;
    }
    Some(if width < 72 {
        "p summary Tab full Space actions"
    } else {
        "p summary · Tab complete document · Space actions · Esc back"
    })
}

pub(crate) const CONTEXT_ACTIONS: [(crossterm::event::KeyCode, &str); 11] = [
    (
        crossterm::event::KeyCode::Char('a'),
        "a Use inspected revision for study",
    ),
    (
        crossterm::event::KeyCode::Char('e'),
        "e Edit an inactive context copy",
    ),
    (
        crossterm::event::KeyCode::Char('c'),
        "c Check source and save inactive",
    ),
    (
        crossterm::event::KeyCode::Char('v'),
        "v Inspect data flow diagram",
    ),
    (
        crossterm::event::KeyCode::Char('m'),
        "m Review producing run as Map",
    ),
    (
        crossterm::event::KeyCode::Char('g'),
        "g Draft budgeted context generation",
    ),
    (crossterm::event::KeyCode::Tab, "Tab Read complete document"),
    (
        crossterm::event::KeyCode::Char('d'),
        "d Compare edited/regenerated text",
    ),
    (crossterm::event::KeyCode::Char('+'), "+ Add context case"),
    (
        crossterm::event::KeyCode::Char('b'),
        "b Set matrix baseline",
    ),
    (
        crossterm::event::KeyCode::Char('p'),
        "p Inspect scanner context",
    ),
];

pub(crate) fn context_actions(app: &ShellApp) -> Vec<(crossterm::event::KeyCode, &'static str)> {
    CONTEXT_ACTIONS
        .into_iter()
        .filter(|(key, _)| action_available(app, *key))
        .map(|(key, label)| (key, context_action_label(app, key, label)))
        .collect()
}

fn context_action_label(
    app: &ShellApp,
    key: crossterm::event::KeyCode,
    label: &'static str,
) -> &'static str {
    let Some(picker) = app.study_context_picker() else {
        return label;
    };
    match key {
        crossterm::event::KeyCode::Char('g') if picker.regeneration_entry => {
            "g Choose text to regenerate"
        }
        crossterm::event::KeyCode::Char('a') if picker.matrix_case_id.is_some() => {
            "a Replace selected case context"
        }
        _ => label,
    }
}

pub(crate) fn action_available(app: &ShellApp, key: crossterm::event::KeyCode) -> bool {
    use crossterm::event::KeyCode;
    if app
        .study_context_picker()
        .is_some_and(|picker| picker.regeneration_entry)
    {
        return !matches!(key, KeyCode::Char('a' | 'm' | '+' | 'b'));
    }
    match key {
        KeyCode::Char('+') | KeyCode::Char('b') => !app
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .is_some_and(|config| config.study.scope_draft.is_some()),
        _ => true,
    }
}

pub(crate) fn context_action_lines(app: &ShellApp) -> Vec<String> {
    let mut lines = vec!["CONTEXT ACTIONS".into()];
    lines.extend(
        context_actions(app)
            .iter()
            .map(|(_, label)| (*label).into()),
    );
    lines.push("↑↓ choose · Enter act · Esc back".into());
    lines
}

pub(crate) fn comparison_lines(
    comparison: &crate::app::StudyContextComparison,
    width: usize,
) -> Vec<String> {
    let mut lines = vec!["Compare saved text. Selection changes this study only.".into()];
    append_comparison_content(&mut lines, comparison);
    lines.extend([
        String::new(),
        format!("Parent: {}", comparison.parent.revision_id),
        format!("Candidate: {}", comparison.candidate.revision_id),
    ]);
    lines
        .into_iter()
        .flat_map(|line| context_wrap(&line, width.max(1)))
        .collect()
}

fn append_comparison_content(
    lines: &mut Vec<String>,
    comparison: &crate::app::StudyContextComparison,
) {
    if let Some(error) = &comparison.error {
        lines.extend([
            format!("Parent unavailable: {error}"),
            "Enter retries this local read · Esc returns to the candidate. No model request."
                .into(),
        ]);
        return;
    }
    let Some(changes) = comparison.differences.as_ref() else {
        lines.push("Reading the authenticated parent. No model request.".into());
        return;
    };
    for change in changes {
        lines.extend([String::new(), change.label.clone(), "Before:".into()]);
        lines.extend(change.before.lines().map(|line| format!("- {line}")));
        lines.push("After:".into());
        lines.extend(change.after.lines().map(|line| format!("+ {line}")));
    }
    if changes.is_empty() {
        lines.push("No editable text differs from the recorded parent.".into());
    }
}

pub(crate) fn context_diagram_model(
    document: &Value,
    target: Option<&std::path::Path>,
) -> super::DfdModel {
    super::viz_data::dfd_model_from_doc(Some(document), target)
}

pub(crate) fn context_reader_layout(
    area: Rect,
    row_count: usize,
    text_view: crate::app::StudyContextTextView,
) -> super::study_config::StudyConfigLayout {
    if text_view == crate::app::StudyContextTextView::Scanner {
        return super::study_config::study_reader_layout(area, true);
    }
    context_layout(area, row_count)
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
    membership_known: bool,
}

pub(crate) struct ContextRow {
    pub(crate) reference: Option<ThreatModelRef>,
    pub(crate) label: String,
    pub(crate) details: Vec<String>,
    pub(crate) copy_label: Option<String>,
}

pub(crate) fn context_catalog(app: &ShellApp) -> ContextCatalog {
    let mut catalog = ContextCatalog {
        rows: vec![initial_context_row(app)],
        status: String::new(),
        membership_known: false,
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
    explain_regeneration_catalog(app, &mut catalog);
    catalog
}

fn explain_regeneration_catalog(app: &ShellApp, catalog: &mut ContextCatalog) {
    if catalog.membership_known
        && app
            .study_context_picker()
            .is_some_and(|p| p.regeneration_entry)
    {
        catalog.status = format!(
            "{} saved revisions. Choose the parent for an inactive copy.",
            catalog.rows.len().saturating_sub(1)
        );
    }
}

fn initial_context_row(app: &ShellApp) -> ContextRow {
    if app
        .study_context_picker()
        .is_some_and(|picker| picker.regeneration_entry)
    {
        return ContextRow { reference: None, label: "Choose a saved revision".into(), copy_label: None,
            details: vec!["Select a revision, press Enter to inspect it, then e to choose text for regeneration. Planning, allowance approval and execution are separate. No request has started.".into()] };
    }
    omission_row()
}

fn omission_row() -> ContextRow {
    ContextRow {
        reference: None, label: "Omit threat-model context".into(), copy_label:None,
        details: vec!["Discovery will receive no threat-model document for this selection. Omission does not establish finding verdicts or repository coverage.".into(), "a saves this explicit omission for the selected study or boundary. No scan starts.".into()],
    }
}

fn append_revisions(catalog: &mut ContextCatalog, manifest: &ThreatModelManifest) {
    catalog.membership_known = true;
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
                copy_label: Some(format!("{} · edited", model.label)),
                details: vec![
                    format!("{} · {}", model.label, model.methodology),
                    format!("Scope: {}", scope.rel_path.display()),
                    format!("Recorded source revision: {}", scope.target_revision),
                    format!(
                        "Last recorded check: {}",
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
    if let Some(draft) = app.context_edit_draft() {
        return super::context_edit::context_edit_plain_lines(
            draft,
            width,
            app.context_checkpoint_note(),
        );
    }
    let Some(picker) = app.study_context_picker() else {
        return Vec::new();
    };
    context_picker_lines(app, picker)
        .into_iter()
        .flat_map(|line| context_wrap(&line, width.max(1)))
        .collect()
}

fn context_picker_lines(app: &ShellApp, picker: &crate::app::StudyContextPicker) -> Vec<String> {
    if picker.text_view == crate::app::StudyContextTextView::Scanner {
        return scanner::picker_lines(picker);
    }
    let catalog = context_catalog(app);
    let mut text = vec![catalog.status, String::new()];
    text.splice(0..0, context_binding_lines(app, picker));
    if let Some(notice) =
        super::study_config::study_projection(app).and_then(|config| config.notice)
    {
        text.extend([notice, String::new()]);
    }
    let selected = catalog
        .rows
        .iter()
        .find(|row| row.reference == picker.selected);
    append_selected_context(&mut text, selected, picker, catalog.membership_known);
    text
}

fn context_binding_lines(app: &ShellApp, picker: &crate::app::StudyContextPicker) -> Vec<String> {
    if let Some(id) = &picker.scope_id {
        return vec![format!("Selection applies only to boundary {id}. a saves an exact override; Esc returns without changing its association.")];
    }
    let Some(id) = picker.matrix_case_id.as_deref() else {
        return Vec::new();
    };
    let name = app
        .router
        .campaign()
        .batch_scan_config
        .as_ref()
        .and_then(|config| config.study.matrix.cases.iter().find(|case| case.id == id))
        .map_or(id, |case| case.label.as_str());
    vec![format!("Selection applies only to case {name}. a replaces its exact revision; Esc returns without changing the case.")]
}

fn append_selected_context(
    text: &mut Vec<String>,
    selected: Option<&ContextRow>,
    picker: &crate::app::StudyContextPicker,
    membership_known: bool,
) {
    match selected {
        Some(row) => text.extend(row.details.iter().take(4).cloned()),
        None => text.push(missing_catalog_membership(membership_known)),
    }
    text.extend(
        picker
            .preview
            .as_ref()
            .map(|preview| preview.source_state.clone()),
    );
    text.extend(preview_lines(picker));
    if let Some(row) = selected {
        text.extend(row.details.iter().skip(4).cloned());
    }
    append_inspected_context_actions(text, picker);
}

fn append_inspected_context_actions(
    text: &mut Vec<String>,
    picker: &crate::app::StudyContextPicker,
) {
    if picker.preview.is_none() {
        return;
    }
    text.push("c checks citations, links, source identity and bounded coverage. No model request. Source drift stops the check; the active context stays unchanged.".into());
    if picker.regeneration_entry {
        text.push("e opens the text fields; g then plans regeneration of the selected field. Review its model, guidance and allowance before execution. The original stays unchanged.".into());
        return;
    }
    text.push(
        "a uses this exact revision. A new study plan must be approved before scanning.".into(),
    );
    text.push(
        "m reviews its producing run as Map for separate acceptance. No model request is made."
            .into(),
    );
}

fn missing_catalog_membership(known: bool) -> String {
    if known {
        "The selected revision is unavailable in this catalog. It cannot be substituted with another revision.".into()
    } else {
        "Catalog membership is unavailable. The exact selected revision is kept; Enter can inspect it.".into()
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
    if picker.text_view == crate::app::StudyContextTextView::Document {
        let mut lines = super::context_goal::context_goal_lines(&preview.goal_state);
        lines.push("Complete selected context document:".into());
        lines.extend(preview.raw.clone());
        return lines;
    }
    let mut lines = vec![
        String::new(),
        "CONTEXT SUMMARY · v diagram · Tab complete document · p scanner context".into(),
    ];
    if let Some(notice) = preview.dfd.evidence_notice() {
        lines.push(notice.into());
    }
    lines.extend(super::context_goal::context_goal_lines(&preview.goal_state));
    lines.extend(context_summary(&preview.document));
    lines
}

pub(crate) fn context_summary(document: &Value) -> Vec<String> {
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
    let answer = value
        .get("answer")
        .and_then(Value::as_str)
        .map(|answer| format!("Answer: {answer}"));
    let mut text = [title, description]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");
    if let Some(answer) = answer {
        text.push_str(&format!(" · {answer}"));
    }
    text
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
    fn scanner_layout_gives_the_document_full_width_and_uses_the_same_controls() {
        use crate::app::StudyContextTextView;
        for (width, height) in [(40, 11), (60, 19), (80, 23), (96, 88), (120, 35), (160, 47)] {
            let area = Rect::new(0, 0, width, height);
            let scanner = context_reader_layout(area, 20, StudyContextTextView::Scanner);
            let summary = context_reader_layout(area, 20, StudyContextTextView::Summary);
            assert_eq!(scanner.list.height, 0);
            assert_eq!(scanner.detail.width, width - 4);
            assert_eq!(scanner.controls, summary.controls);
            assert!(scanner.detail.height >= summary.detail.height);
            assert!(scanner.detail.bottom() <= scanner.controls.y);
        }
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
