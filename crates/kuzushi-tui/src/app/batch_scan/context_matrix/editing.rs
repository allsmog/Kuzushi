//! Edit a draft case without changing its identity, baseline or spending.
use super::*;
use crate::app::{FieldEditor, ShellView};
use crossterm::event::{KeyEvent, KeyModifiers};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ContextCaseNameEdit {
    pub(crate) case_id: String,
    pub(crate) field: FieldEditor,
    pub(crate) error: Option<String>,
    pub(crate) open: bool,
}

impl BatchScanConfig {
    pub(crate) fn context_case_name_edit(&self) -> Option<&ContextCaseNameEdit> {
        self.study
            .matrix
            .name_edit
            .as_ref()
            .filter(|edit| edit.open)
    }

    fn save_context_case_name(&mut self) -> anyhow::Result<()> {
        let edit = self.context_case_name_edit().unwrap();
        let index = self
            .study
            .matrix
            .cases
            .iter()
            .position(|case| case.id == edit.case_id)
            .ok_or_else(|| anyhow::anyhow!("This case was removed. Return to the case list."))?;
        let mut case = self.study.matrix.cases[index].clone();
        case.label = edit.field.text().trim().to_owned();
        case.validate()?;
        if case != self.study.matrix.cases[index] {
            self.study.matrix.cases[index] = case;
            self.study.invalidate_plan();
        }
        self.study.matrix.name_edit = None;
        self.notice =
            Some("Case name saved. Changes need new approval; spending is retained.".into());
        Ok(())
    }
}

impl ShellApp {
    pub(super) fn begin_context_case_name_edit(&mut self) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(case) = config.study.matrix.cases.get(config.study.matrix.cursor) else {
            return;
        };
        let edit = config
            .study
            .matrix
            .name_edit
            .get_or_insert_with(|| ContextCaseNameEdit {
                case_id: case.id.clone(),
                field: FieldEditor::new(&case.label),
                error: None,
                open: true,
            });
        if edit.case_id != case.id {
            *edit = ContextCaseNameEdit {
                case_id: case.id.clone(),
                field: FieldEditor::new(&case.label),
                error: None,
                open: true,
            };
        }
        edit.open = true;
    }

    pub(crate) fn context_case_name_editor_open(&self) -> bool {
        self.shell_view() == ShellView::Campaign
            && self
                .router
                .campaign()
                .batch_scan_config
                .as_ref()
                .is_some_and(|config| config.context_case_name_edit().is_some())
    }

    pub(crate) fn handle_context_case_name_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.context_case_name_editor_open()
            || (key.modifiers == KeyModifiers::CONTROL
                && matches!(key.code, KeyCode::Char('c' | 'd')))
        {
            return None;
        }
        let config = self.router.campaign_mut().batch_scan_config.as_mut()?;
        edit_name_key(config, key);
        Some(InputUpdate::handled())
    }

    pub(crate) fn capture_context_case_name_paste(&mut self, text: &str) -> bool {
        if !self.context_case_name_editor_open() {
            return false;
        }
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        let edit = config.study.matrix.name_edit.as_mut().unwrap();
        edit.field.insert(text);
        edit.error = None;
        self.checkpoint_study_choices();
        true
    }

    pub(super) fn inspect_selected_context_case(&mut self) -> InputUpdate {
        let Some(case) = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .and_then(|config| config.study.matrix.cases.get(config.study.matrix.cursor))
            .cloned()
        else {
            return InputUpdate::handled();
        };
        self.install_study_context_picker(json!({"threatModelRef":case.threat_model_ref}));
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        let Some(picker) = config.context_picker.as_mut() else {
            return InputUpdate::handled();
        };
        picker.matrix_case_id = Some(case.id);
        config.study.matrix.open = false;
        self.inspect_study_context()
    }

    pub(in crate::app::batch_scan) fn replace_context_case(
        &mut self,
        id: &str,
        reference: serde_json::Value,
    ) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        if let Err(error) = replace_case_reference(config, id, reference) {
            config.notice = Some(format!("Case context unchanged: {error}"));
            return;
        }
        config.context_picker = None;
        config.study.matrix.open = true;
        config.notice =
            Some("Case context selected. Changes need new approval; spending is retained.".into());
    }
}

fn edit_name_key(config: &mut BatchScanConfig, key: KeyEvent) {
    if key == KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE) {
        if let Err(error) = config.save_context_case_name() {
            config.study.matrix.name_edit.as_mut().unwrap().error = Some(error.to_string());
        }
        return;
    }
    let edit = config.study.matrix.name_edit.as_mut().unwrap();
    if key.code == KeyCode::Esc {
        edit.open = false;
        return;
    }
    edit.field.handle_key(key);
    edit.error = None;
}

fn replace_case_reference(
    config: &mut BatchScanConfig,
    id: &str,
    reference: serde_json::Value,
) -> anyhow::Result<()> {
    let index = config
        .study
        .matrix
        .cases
        .iter()
        .position(|case| case.id == id)
        .ok_or_else(|| anyhow::anyhow!("This case was removed. Return to the case list."))?;
    anyhow::ensure!(
        !config
            .study
            .matrix
            .cases
            .iter()
            .any(|case| case.id != id && case.threat_model_ref == reference),
        "This exact context is already included. Use repetitions for identical conditions."
    );
    let mut case = config.study.matrix.cases[index].clone();
    case.threat_model_ref = reference;
    case.validate()?;
    if case != config.study.matrix.cases[index] {
        config.study.matrix.cases[index] = case;
        config.study.invalidate_plan();
    }
    Ok(())
}
