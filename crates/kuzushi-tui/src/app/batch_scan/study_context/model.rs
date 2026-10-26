use super::{StudyContextDiagram, StudyContextTextView};
use anyhow::Context;
use kuzushi_core::ThreatModelRef;
use serde_json::Value;
use std::sync::Arc;

use super::super::context_check::ContextCheckReaderOrigin;
use super::super::context_generation::StudyContextGeneration;
use super::super::StudyContextComparison;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct StudyContextPicker {
    pub(crate) regeneration_entry: bool,
    pub(crate) scope_id: Option<String>,
    pub(crate) matrix_case_id: Option<String>,
    pub(crate) scan_input: Value,
    pub(crate) selected: Option<ThreatModelRef>,
    pub(crate) preview: Option<Arc<StudyContextPreview>>,
    pub(crate) detail_scroll: usize,
    pub(crate) text_view: StudyContextTextView,
    pub(crate) diagram: Option<StudyContextDiagram>,
    pub(crate) diagram_visible: bool,
    pub(crate) editor_visible: bool,
    pub(crate) actions_selected: Option<usize>,
    pub(crate) pending_check: Option<ThreatModelRef>,
    pub(crate) pending_check_origin: Option<ContextCheckReaderOrigin>,
    pub(crate) comparison: Option<StudyContextComparison>,
    pub(crate) map_attempt_id: Option<String>,
    pub(crate) return_generation: Option<Box<StudyContextGeneration>>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StudyContextPreview {
    pub(crate) document: Value,
    pub(crate) raw: Vec<String>,
    pub(crate) dfd: crate::ui_view_models::DfdModel,
    pub(crate) source_state: String,
    pub(crate) source_status: Option<String>,
    pub(crate) lesson_usable: bool,
    pub(crate) goal_state: Value,
    pub(crate) scanner_context: Value,
}

pub(super) fn context_preview(
    data: &Value,
    target: Option<&std::path::Path>,
) -> anyhow::Result<Arc<StudyContextPreview>> {
    let document = data
        .get("document")
        .filter(|value| value.is_object())
        .context("The exact context reader returned no document.")?;
    let text = serde_json::to_string_pretty(document)?;
    Ok(Arc::new(StudyContextPreview {
        lesson_usable: data
            .pointer("/lessonState/usable")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        document: document.clone(),
        raw: text.lines().map(str::to_string).collect(),
        dfd: crate::ui_view_models::study_context::context_diagram_model(document, target),
        source_state: context_read_state(data),
        source_status: data
            .pointer("/sourceState/status")
            .and_then(Value::as_str)
            .map(str::to_owned),
        goal_state: data["goalState"].clone(),
        scanner_context: data["scannerContextPreview"].clone(),
    }))
}

fn context_read_state(data: &Value) -> String {
    let source=data.pointer("/sourceState/message").and_then(Value::as_str).unwrap_or("Source identity was not checked in this receipt. Treat the recorded check as historical.");
    if data.pointer("/lessonState/usable").and_then(Value::as_bool) == Some(false) {
        return format!(
            "{source} Lesson context needs review: {}",
            data.pointer("/lessonState/reason")
                .and_then(Value::as_str)
                .unwrap_or("origin unavailable")
        );
    }
    source.into()
}

pub(super) fn matching_saved_context(input: &Value, reference: &ThreatModelRef) -> bool {
    input["threatModelRef"] == serde_json::json!(reference)
        && input.get("threatModelDigestRef").is_some()
}

pub(super) fn context_selection_ready(picker: &StudyContextPicker) -> Result<(), &'static str> {
    if picker.selected.is_some() && picker.preview.is_none() {
        return Err("Inspect this exact revision with Enter before using it.");
    }
    if picker
        .preview
        .as_ref()
        .is_some_and(|preview| !preview.lesson_usable)
    {
        return Err("This context contains a changed or retired lesson. Create a copy with a fresh reviewed selection before using it.");
    }
    Ok(())
}
