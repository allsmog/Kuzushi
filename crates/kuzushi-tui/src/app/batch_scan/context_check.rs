use super::study_context::StudyContextPicker;
use crate::app::{state_transitions::InputUpdate, ShellApp};
use anyhow::Context;
use kuzushi_core::ThreatModelRef;
use serde_json::{json, Value};

mod actions;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContextCheckReaderOrigin {
    scroll: usize,
    raw: bool,
}

fn reader_origin(picker: &StudyContextPicker) -> ContextCheckReaderOrigin {
    ContextCheckReaderOrigin {
        scroll: picker.detail_scroll,
        raw: picker.raw,
    }
}

fn check_reader_unchanged(picker: &StudyContextPicker, source: &ThreatModelRef) -> bool {
    picker.selected.as_ref() == Some(source)
        && picker.pending_check_origin == Some(reader_origin(picker))
}

fn check_reader_visible(picker: &StudyContextPicker) -> bool {
    !picker.editor_visible && !picker.diagram_visible && picker.actions_selected.is_none()
}

impl ShellApp {
    pub(super) fn check_study_context(&mut self) -> InputUpdate {
        let reference = self
            .study_context_picker()
            .and_then(|picker| picker.selected.clone().filter(|_| picker.preview.is_some()));
        let Some(reference) = reference else {
            self.set_batch_config_notice(
                "Inspect an exact revision with Enter before checking its source.",
            );
            return InputUpdate::handled();
        };
        if self.has_running_work() {
            self.set_batch_config_notice("Wait for active work before checking context source.");
            return InputUpdate::handled();
        }
        self.edit_context_picker(|config| {
            let picker = config.context_picker.as_mut().unwrap();
            picker.pending_check_origin = Some(reader_origin(picker));
            picker.pending_check = Some(reference.clone());
            config.notice = Some("Checking citations, links, source identity and bounded coverage. No model request. A saved check stays inactive.".into());
        });
        InputUpdate::handled_with_effects(self.reduce_run_tool(
            Some("threat-model:verify".into()),
            Some(json!({"threatModelRef":reference}).to_string()),
        ))
    }

    pub(super) fn cache_context_check_result(&mut self, data: &Value) -> bool {
        if data["resolvedFrom"] != "exact-verification" {
            return false;
        }
        if let Err(error) = self.apply_context_check_result(data) {
            self.context_check_failed(
                "threat-model:verify",
                &format!("Receipt unavailable: {error:#}"),
            );
        }
        true
    }

    fn apply_context_check_result(&mut self, data: &Value) -> anyhow::Result<()> {
        let target = data["target"].as_str().context("Check target is missing")?;
        if self.target() != Some(std::path::Path::new(target)) {
            return Ok(());
        }
        let source: ThreatModelRef = serde_json::from_value(data["sourceModelRef"].clone())?;
        let Some(picker) = self.study_context_picker() else {
            return Ok(());
        };
        if picker.pending_check.as_ref() != Some(&source) {
            return Ok(());
        }
        let written = checked_reference(data)?;
        let matching = check_reader_unchanged(picker, &source) && check_reader_visible(picker);
        anyhow::ensure!(data["document"].is_object(), "Checked document is missing");
        self.edit_context_picker(|config| {
            let picker = config.context_picker.as_mut().unwrap();
            picker.pending_check = None;
            picker.pending_check_origin = None;
            if matching {
                select_checked_revision(picker, written);
            }
            config.notice = Some(check_notice(data, matching));
        });
        Ok(())
    }

    pub(crate) fn context_check_failed(&mut self, tool: &str, error: &str) {
        if tool != "threat-model:verify" {
            return;
        }
        self.edit_context_picker(|config| {
            let Some(picker) = config.context_picker.as_mut() else { return; };
            if picker.pending_check.take().is_some() {
                mark_inspection_uncertain(picker);
                config.notice = Some(format!("Context check stopped: {error}. The selected context is kept. Inspect Activity and the catalog before retrying."));
                picker.pending_check_origin = None;
            }
        });
    }
}

fn mark_inspection_uncertain(picker: &mut StudyContextPicker) {
    if let Some(preview) = picker.preview.as_mut() {
        std::sync::Arc::make_mut(preview).source_state = "The source check stopped. Treat the recorded check as historical; inspect again to compare source identity.".into();
    }
}

fn checked_reference(data: &Value) -> anyhow::Result<ThreatModelRef> {
    anyhow::ensure!(
        data["activated"] == false && data["written"] == true,
        "Check receipt did not confirm an inactive saved revision"
    );
    serde_json::from_value(data["modelRef"].clone())
        .context("Checked revision reference is missing")
}

fn select_checked_revision(picker: &mut StudyContextPicker, reference: ThreatModelRef) {
    picker.selected = Some(reference);
    picker.preview = None;
    picker.detail_scroll = 0;
    picker.raw = false;
    picker.diagram = None;
    picker.diagram_visible = false;
    picker.map_attempt_id = None;
}

fn check_notice(data: &Value, matching: bool) -> String {
    if data["sourceCheckCurrent"] != true {
        return "Source could not be authenticated after checking. Inspect Activity and the saved revision before further work; its current-source status is unverified.".into();
    }
    let verdict = data["verification"]["verdict"]
        .as_str()
        .unwrap_or("unavailable");
    if !matching {
        return format!(
            "Context source check: {verdict}. Saved {}. Your selection is unchanged.",
            data["modelRef"]["revisionId"]
                .as_str()
                .unwrap_or("revision unavailable")
        );
    }
    format!("Context source check: {verdict}. Enter inspects the saved check; a uses it after inspection. Active context is unchanged.")
}
