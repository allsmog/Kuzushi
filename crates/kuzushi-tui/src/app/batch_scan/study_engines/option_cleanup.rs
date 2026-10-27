use super::StudyEnginePicker;
use crate::app::ShellApp;
use anyhow::{Context, Result};
use kuzushi_core::modules::{inactive_scan_task_options, InactiveScanTaskOptions};
use serde_json::Value;

impl StudyEnginePicker {
    pub(crate) fn inactive_options(&self) -> Result<Vec<InactiveScanTaskOptions>> {
        inactive_scan_task_options(&self.prepared_selection())
    }

    fn clear_inactive_options(&mut self) -> Result<()> {
        let options = self
            .inactive_options()?
            .into_iter()
            .flat_map(|group| group.options)
            .collect::<Vec<_>>();
        if options.is_empty() {
            return Ok(());
        }
        let input = self
            .input
            .as_object_mut()
            .context("Engine draft must be an object")?;
        for option in &options {
            input.remove(option);
        }
        self.scroll = 0;
        self.notice = Some(format!("Cleared {} from this draft. Apply to use it; Esc keeps the original study. Global settings and spending are unchanged.", options.join(", ")));
        Ok(())
    }
}

pub(super) fn validated_engine_selection(picker: &StudyEnginePicker) -> Result<Value> {
    let input = picker.prepared_selection();
    kuzushi_core::modules::validate_scan_scope_contract(&input)?;
    let options = inactive_scan_task_options(&input)?
        .into_iter()
        .flat_map(|group| group.options)
        .collect::<Vec<_>>();
    anyhow::ensure!(options.is_empty(), "Settings belong to unselected engines: {}. Press c to clear them in this draft, or select their engines. No changes applied.", options.join(", "));
    Ok(input)
}

impl ShellApp {
    pub(super) fn clear_study_engine_options(&mut self) {
        let Some(picker) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.engine_picker.as_mut())
        else {
            return;
        };
        if let Err(error) = picker.clear_inactive_options() {
            picker.notice = Some(format!("Options unchanged: {error:#}"));
        }
    }
}
