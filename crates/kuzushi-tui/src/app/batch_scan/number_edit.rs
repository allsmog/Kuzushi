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
    pub(crate) fn bounds(&self) -> (usize, usize) {
        match self.row {
            BatchScanConfigRow::Trials => (MIN_BATCH_TRIALS, BATCH_HARD_CAP),
            _ => (1, MAX_BATCH_WORKERS),
        }
    }

    fn value(&self) -> Result<usize, String> {
        let (minimum, maximum) = self.bounds();
        self.field
            .text()
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|value| (minimum..=maximum).contains(value))
            .ok_or_else(|| format!("Enter a whole number from {minimum} to {maximum}."))
    }
}

impl BatchScanConfig {
    pub(crate) fn begin_number_edit(&mut self, row: BatchScanConfigRow) {
        if !matches!(
            row,
            BatchScanConfigRow::Trials | BatchScanConfigRow::Workers
        ) {
            return;
        }
        self.number_edit = Some(BatchNumberEdit {
            row,
            field: FieldEditor::default(),
            error: None,
        });
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
        match edit.row {
            BatchScanConfigRow::Trials => self.trials = value,
            _ => self.requested_workers = value,
        }
        self.number_edit = None;
        self.disarm_review();
        true
    }
}

impl ShellApp {
    pub(crate) fn batch_config_open(&self) -> bool {
        self.shell_view() == ShellView::Campaign
            && self.router.campaign().batch_scan_config.is_some()
    }

    pub(crate) fn handle_batch_config_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if let Some(update) = self.handle_batch_number_key(key) {
            return Some(update);
        }
        if self.batch_config_open() && key.modifiers.is_empty() && key.code == KeyCode::Esc {
            return Some(self.close_batch_config());
        }
        None
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
