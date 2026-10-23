use crate::app::{state_transitions::InputUpdate, ShellApp};
use anyhow::Context;
use crossterm::event::KeyCode;
use kuzushi_core::{
    capabilities::threat_model::{context_text_differences, ContextTextDifference},
    ThreatModelRef,
};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StudyContextComparison {
    pub target: std::path::PathBuf,
    pub parent: ThreatModelRef,
    pub candidate: ThreatModelRef,
    pub differences: Option<Vec<ContextTextDifference>>,
    pub error: Option<String>,
    pub scroll: usize,
}

impl ShellApp {
    pub(in crate::app::batch_scan) fn compare_study_context(&mut self) -> InputUpdate {
        if self.has_running_work() {
            self.set_batch_config_notice("Wait for active work before comparing context.");
            return InputUpdate::handled();
        }
        match self.context_comparison_input() {
            Ok(comparison) => {
                let parent = comparison.parent.clone();
                self.edit_context_picker(|config| {
                    config.context_picker.as_mut().unwrap().comparison = Some(comparison)
                });
                InputUpdate::handled_with_effects(self.reduce_run_tool(
                    Some("threat-model:read".into()),
                    Some(json!({"threatModelRef":parent}).to_string()),
                ))
            }
            Err(error) => {
                self.set_batch_config_notice(format!("Comparison unavailable: {error:#}"));
                InputUpdate::handled()
            }
        }
    }

    fn context_comparison_input(&self) -> anyhow::Result<StudyContextComparison> {
        let picker = self
            .study_context_picker()
            .context("Choose a context first")?;
        let candidate = picker
            .selected
            .clone()
            .context("Choose an exact context revision")?;
        let preview = picker
            .preview
            .as_ref()
            .context("Inspect the exact candidate with Enter first")?;
        let parent = preview
            .document
            .pointer("/provenance/regeneration/sourceModelRef")
            .or_else(|| {
                preview
                    .document
                    .pointer("/provenance/operatorEdit/sourceModelRef")
            })
            .or_else(|| {
                preview
                    .document
                    .pointer("/provenance/fileContext/receipt/inheritedContextRef")
            })
            .context("This context has no recorded edited, regenerated or inherited parent")?;
        Ok(StudyContextComparison {
            target: self
                .target_owned()
                .context("Select a target before comparing context")?,
            parent: serde_json::from_value(parent.clone())?,
            candidate,
            differences: None,
            error: None,
            scroll: 0,
        })
    }

    pub(in crate::app::batch_scan) fn cache_context_comparison(&mut self, data: &Value) -> bool {
        let Some(picker) = self.study_context_picker() else {
            return false;
        };
        let Some(comparison) = picker.comparison.as_ref() else {
            return false;
        };
        if !matches_parent_receipt(self, data, comparison) {
            return false;
        }
        let Some(preview) = picker.preview.as_ref() else {
            return false;
        };
        let outcome = data
            .get("document")
            .filter(|value| value.is_object())
            .context("The exact parent reader returned no document")
            .map(|parent| context_text_differences(parent, &preview.document));
        self.edit_context_picker(|config| {
            let comparison = config
                .context_picker
                .as_mut()
                .unwrap()
                .comparison
                .as_mut()
                .unwrap();
            match outcome {
                Ok(differences) => comparison.differences = Some(differences),
                Err(error) => comparison.error = Some(error.to_string()),
            }
        });
        true
    }

    pub(in crate::app::batch_scan) fn handle_context_comparison_key(
        &mut self,
        code: KeyCode,
    ) -> Option<InputUpdate> {
        let comparison = self.study_context_picker()?.comparison.as_ref()?;
        if code == KeyCode::Enter && comparison.error.is_some() {
            return Some(self.compare_study_context());
        }
        if code == KeyCode::Char('a') && comparison.differences.is_some() {
            self.edit_context_picker(|config| {
                config.context_picker.as_mut().unwrap().comparison = None
            });
            return Some(self.handle_study_context_key(code));
        }
        let page = self.viewport().rows.saturating_sub(6).max(1) as usize;
        self.edit_context_picker(|config| {
            update_comparison_key(config.context_picker.as_mut().unwrap(), code, page)
        });
        Some(InputUpdate::handled())
    }
}

impl ShellApp {
    pub(crate) fn context_comparison_failed(&mut self, tool: &str, error: &str) {
        if tool != "threat-model:read" {
            return;
        }
        let target = self.target_owned();
        self.edit_context_picker(|config| {
            let comparison = config
                .context_picker
                .as_mut()
                .and_then(|picker| picker.comparison.as_mut());
            if let Some(comparison) =
                comparison.filter(|comparison| Some(&comparison.target) == target.as_ref())
            {
                comparison.error = Some(error.into());
            }
        });
    }
}

fn matches_parent_receipt(
    app: &ShellApp,
    data: &Value,
    comparison: &StudyContextComparison,
) -> bool {
    data["target"].as_str().map(std::path::Path::new) == Some(comparison.target.as_path())
        && app.target() == Some(comparison.target.as_path())
        && serde_json::from_value::<ThreatModelRef>(data["modelRef"].clone())
            .ok()
            .as_ref()
            == Some(&comparison.parent)
        && app
            .study_context_picker()
            .and_then(|picker| picker.selected.as_ref())
            == Some(&comparison.candidate)
}

fn update_comparison_key(picker: &mut super::StudyContextPicker, code: KeyCode, page: usize) {
    if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
        picker.comparison = None;
        return;
    }
    let comparison = picker.comparison.as_mut().unwrap();
    match code {
        KeyCode::PageUp => comparison.scroll = comparison.scroll.saturating_sub(page),
        KeyCode::PageDown => comparison.scroll = comparison.scroll.saturating_add(page),
        _ => {}
    }
}
