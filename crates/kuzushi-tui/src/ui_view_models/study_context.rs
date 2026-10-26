//! Read-only context catalog and document projection. No active-model mutation.
use crate::app::{ShellApp, ThreatModelStoreState};
use crate::renderer::shared::text::{wrap_document_lines, wrap_text};
use crate::ViewDataState;
use kuzushi_core::{ThreatModelManifest, ThreatModelRef};
use ratatui::layout::Rect;
use serde_json::Value;
use std::time::{Duration, SystemTime};

mod catalog;
pub(crate) mod comparison;
pub(crate) mod diagram;
mod document;
mod evidence;
mod reader;
mod scanner;
mod verification;

#[cfg(test)]
use catalog::context_age;
pub(crate) use catalog::{context_catalog, context_identity, ContextCatalog, ContextRow};
pub(crate) use document::context_summary;

pub(super) fn context_source_receipt_lines(provenance: &Value) -> Vec<String> {
    evidence::provenance_lines(provenance)
}

pub(crate) fn context_header_title(app: &ShellApp) -> &'static str {
    let picker = app.study_context_picker();
    if picker.is_some_and(|picker| picker.text_view == crate::app::StudyContextTextView::Scanner) {
        return " SCANNER CONTEXT PREVIEW ";
    }
    if picker.is_some_and(|picker| picker.preview.is_some()) {
        return if picker
            .is_some_and(|picker| picker.text_view == crate::app::StudyContextTextView::Document)
        {
            " CONTEXT DOCUMENT "
        } else {
            " CONTEXT SUMMARY "
        };
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
        "d Compare saved context revisions",
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
    comparison::all_lines(comparison, width)
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
    inspected: bool,
) -> super::study_config::StudyConfigLayout {
    if inspected || text_view == crate::app::StudyContextTextView::Scanner {
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
    reader::picker_lines(app, picker)
        .into_iter()
        .flat_map(|line| context_wrap(&line, width.max(1)))
        .collect()
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
    wrap_document_lines(
        vec![ratatui::text::Line::raw(line[indent..].to_owned())],
        width.saturating_sub(indent).max(1).min(u16::MAX as usize) as u16,
    )
    .into_iter()
    .map(|line| format!("{prefix}{line}"))
    .collect()
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
            let scanner = context_reader_layout(area, 20, StudyContextTextView::Scanner, true);
            let summary = context_reader_layout(area, 20, StudyContextTextView::Summary, false);
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
    fn missing_catalog_name_keeps_the_exact_inspected_revision_visible() {
        let reference = ThreatModelRef {
            model_id: kuzushi_core::ThreatModelId::new(),
            revision_id: kuzushi_core::ThreatModelRevisionId::new(),
            sha256: "sha256:selected-digest".into(),
        };
        assert_eq!(
            context_identity(&[], Some(&reference)),
            format!("Context: {}", reference.revision_id)
        );
        assert_eq!(context_identity(&[], None), "Context: no revision selected");
    }

    #[test]
    fn study_context_age_discloses_invalid_values() {
        assert!(context_age("0").contains("ago"));
        assert_eq!(context_age("unknown"), "unavailable (unknown)");
    }
}
