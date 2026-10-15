use super::config::{BATCH_HARD_CAP, MAX_BATCH_WORKERS, MIN_BATCH_TRIALS};
use super::{BatchScanConfig, BatchScanConfigRow};
use crate::app::state_transitions::InputUpdate;
use crate::app::{FieldEditor, ShellApp, ShellView};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BatchNumberEdit {
    pub(crate) row: BatchScanConfigRow,
    pub(crate) field: FieldEditor,
    pub(crate) error: Option<String>,
}

impl BatchNumberEdit {
    pub(crate) fn bounds(&self) -> Option<(usize, usize)> {
        self.row.number_bounds()
    }

    fn value(&self) -> Result<usize, String> {
        let (minimum, maximum) = self
            .bounds()
            .ok_or_else(|| "This row is not a numeric field.".to_string())?;
        self.field
            .text()
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|value| (minimum..=maximum).contains(value))
            .ok_or_else(|| format!("Enter a whole number from {minimum} to {maximum}."))
    }
}

impl BatchScanConfigRow {
    pub(crate) fn number_bounds(self) -> Option<(usize, usize)> {
        [
            (Self::Trials, MIN_BATCH_TRIALS, BATCH_HARD_CAP),
            (Self::Workers, 1, MAX_BATCH_WORKERS),
            (Self::ProviderCalls, 0, 1_000_000),
            (Self::ReviewCalls, 0, 1_000_000),
            (Self::Attempts, 1, 10),
            (Self::CasePasses, 1, 100),
        ]
        .into_iter()
        .find(|(row, _, _)| *row == self)
        .map(|(_, min, max)| (min, max))
    }
}

impl BatchScanConfig {
    pub(crate) fn begin_number_edit(&mut self, row: BatchScanConfigRow) {
        if row.number_bounds().is_none() {
            return;
        }
        self.number_edit = Some(BatchNumberEdit {
            row,
            field: FieldEditor::default(),
            error: None,
        });
    }

    fn apply_number(&mut self, row: BatchScanConfigRow, value: usize) {
        if self.apply_case_number(row, value) {
            return;
        }
        match row {
            BatchScanConfigRow::Trials => {
                self.trials = value;
                super::scope_study::update_passes(self, value);
                self.study.invalidate_plan();
            }
            BatchScanConfigRow::Workers => {
                self.requested_workers = value;
                self.study.invalidate_plan();
            }
            _ => self.apply_allowance_number(row, value),
        }
    }

    fn apply_case_number(&mut self, row: BatchScanConfigRow, value: usize) -> bool {
        if row != BatchScanConfigRow::CasePasses {
            return false;
        };
        if let Some(case) = self.study.matrix.cases.get_mut(self.study.matrix.cursor) {
            case.passes = value;
            self.study.invalidate_plan();
        }
        true
    }

    fn apply_allowance_number(&mut self, row: BatchScanConfigRow, value: usize) {
        match row {
            BatchScanConfigRow::ProviderCalls => self.study.max_provider_calls = Some(value),
            BatchScanConfigRow::ReviewCalls => self.study.protected_review_calls = Some(value),
            _ => self.study.max_job_attempts = value,
        }
    }

    fn save_number_edit(&mut self) -> bool {
        let Some(edit) = self.number_edit.as_mut() else {
            return false;
        };
        let value = match edit.value() {
            Ok(value) => value,
            Err(error) => {
                edit.error = Some(error);
                return false;
            }
        };
        let row = edit.row;
        self.apply_number(row, value);
        self.number_edit = None;
        self.notice = None;
        true
    }
}

impl ShellApp {
    pub(crate) fn batch_config_open(&self) -> bool {
        self.shell_view() == ShellView::Campaign
            && self.router.campaign().batch_scan_config.is_some()
    }

    pub(crate) fn handle_batch_config_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let update = self.handle_batch_config_input(key);
        self.checkpoint_study_choices();
        update
    }

    fn handle_batch_config_input(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if self.study_draft_recovery_open() && !batch_editor_yields_to_exit(key) {
            return Some(self.study_recovery_input(key.code));
        }
        if let Some(update) = self.handle_batch_number_key(key) {
            return Some(update);
        }
        if !self.batch_config_open() || batch_editor_yields_to_exit(key) {
            return None;
        }
        Some(self.handle_study_form_key(key))
    }

    pub(crate) fn batch_number_editor_open(&self) -> bool {
        self.shell_view() == ShellView::Campaign
            && self
                .router
                .campaign()
                .batch_scan_config
                .as_ref()
                .is_some_and(|config| config.number_edit.is_some())
    }

    pub(crate) fn handle_batch_number_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.batch_number_editor_open() || batch_editor_yields_to_exit(key) {
            return None;
        }
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            if edit_batch_number_key(config, key) {
                self.refresh_batch_worker_resolution();
            }
        }
        Some(InputUpdate::handled())
    }

    pub(crate) fn capture_batch_number_paste(&mut self, text: &str) -> bool {
        if !self.batch_number_editor_open() {
            return false;
        }
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return false;
        };
        if let Some(edit) = config.number_edit.as_mut() {
            edit.field.insert(text);
            edit.error = None;
        }
        self.checkpoint_study_choices();
        true
    }
}

fn batch_editor_yields_to_exit(key: KeyEvent) -> bool {
    key.modifiers == KeyModifiers::CONTROL && matches!(key.code, KeyCode::Char('c' | 'd'))
}

/// Saving only changes configuration. Launch is a separate action after the
/// field closes, and shared worker/budget policy still resolves the request.
fn edit_batch_number_key(config: &mut BatchScanConfig, key: KeyEvent) -> bool {
    if key.modifiers.is_empty() && key.code == KeyCode::Enter {
        return config.save_number_edit();
    }
    if key.modifiers.is_empty() && key.code == KeyCode::Esc {
        config.number_edit = None;
        return false;
    }
    if let Some(edit) = config.number_edit.as_mut() {
        edit.field.handle_key(key);
        edit.error = None;
    }
    false
}

#[cfg(test)]
mod tests;
