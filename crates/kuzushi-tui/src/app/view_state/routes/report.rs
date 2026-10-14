use crate::app::FieldEditor;
use crossterm::event::KeyEvent;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRouteState {
    format_index: usize,
    completeness: kuzushi_core::WorkspaceExportCompleteness,
    workspace_history: bool,
    provenance_details: bool,
    paths: [String; 6],
    path_edit: Option<FieldEditor>,
    path_error: Option<String>,
    origin: Option<ReportOrigin>,
    receipt: Option<ReportReceipt>,
    reveal_error: Option<String>,
    study: Option<ReportStudyRef>,
    choices_target: Option<PathBuf>,
    choices_error: Option<String>,
    choices_saved: bool,
}

impl Default for ReportRouteState {
    fn default() -> Self {
        Self {
            format_index: 0,
            completeness: kuzushi_core::WorkspaceExportCompleteness::All,
            workspace_history: false,
            provenance_details: false,
            paths: Self::FORMATS.map(|format| default_report_path(format).to_string()),
            path_edit: None,
            path_error: None,
            origin: None,
            receipt: None,
            reveal_error: None,
            study: None,
            choices_target: None,
            choices_error: None,
            choices_saved: false,
        }
    }
}

impl ReportRouteState {
    pub(crate) fn choices_target(&self) -> Option<&std::path::Path> {
        self.choices_target.as_deref()
    }

    pub(crate) fn prepare_choices_target(&mut self, target: PathBuf) {
        let fresh = Self::default();
        self.format_index = fresh.format_index;
        self.completeness = fresh.completeness;
        self.paths = fresh.paths;
        self.provenance_details = false;
        self.path_edit = None;
        self.path_error = None;
        self.choices_target = Some(target);
        self.choices_error = None;
        self.choices_saved = false;
    }

    pub(crate) fn captured_choices(
        &self,
        target: PathBuf,
    ) -> kuzushi_core::workspace::report_preferences::ReportPreferences {
        kuzushi_core::workspace::report_preferences::ReportPreferences {
            schema_version: 1,
            target,
            format: self.format(),
            completeness: self.completeness,
            destinations: Self::FORMATS
                .iter()
                .zip(&self.paths)
                .map(|(format, path)| (format.as_str().into(), path.clone()))
                .collect(),
            provenance_details: self.provenance_details,
        }
    }

    pub(crate) fn restore_choices(
        &mut self,
        choices: kuzushi_core::workspace::report_preferences::ReportPreferences,
    ) -> Result<(), String> {
        choices
            .validate(&choices.target)
            .map_err(|error| error.to_string())?;
        let index = Self::FORMATS
            .iter()
            .position(|format| *format == choices.format)
            .ok_or("Unsupported saved report format")?;
        self.format_index = index;
        self.paths = Self::FORMATS.map(|format| choices.destinations[format.as_str()].clone());
        self.completeness = choices.completeness;
        self.provenance_details = choices.provenance_details;
        self.choices_saved = true;
        self.choices_error = None;
        Ok(())
    }

    pub(crate) fn record_choices_save(&mut self, result: Result<(), String>) {
        self.choices_saved = result.is_ok();
        self.choices_error = result.err();
    }

    pub(crate) fn choices_status(&self) -> String {
        if let Some(error) = &self.choices_error {
            return format!("Saved choices unavailable: {error}. Current choices are shown.");
        }
        if self.choices_saved {
            return "Saved for this target; S updates choices without exporting.".into();
        }
        "Session choices; S saves them for restart. Export also saves choices.".into()
    }

    pub(crate) fn study(&self) -> Option<&ReportStudyRef> {
        self.study.as_ref()
    }

    pub(crate) fn set_study(&mut self, study: Option<ReportStudyRef>) {
        self.study = study;
        self.workspace_history = false;
        self.receipt = None;
        self.reveal_error = None;
    }
    pub(crate) fn provenance_details(&self) -> bool {
        self.provenance_details
    }

    pub(crate) fn toggle_provenance(&mut self) {
        self.provenance_details = !self.provenance_details;
        self.choices_saved = false;
    }

    pub(crate) fn workspace_history(&self) -> bool {
        self.workspace_history
    }

    pub(crate) fn toggle_scope(&mut self) {
        self.workspace_history = !self.workspace_history;
        self.receipt = None;
        self.reveal_error = None;
    }

    pub(crate) const FORMATS: [kuzushi_core::WorkspaceExportFormat; 6] = [
        kuzushi_core::WorkspaceExportFormat::Sarif,
        kuzushi_core::WorkspaceExportFormat::MarkdownBundle,
        kuzushi_core::WorkspaceExportFormat::Jsonl,
        kuzushi_core::WorkspaceExportFormat::Json,
        kuzushi_core::WorkspaceExportFormat::Csv,
        kuzushi_core::WorkspaceExportFormat::VulnFindings,
    ];

    pub(crate) fn format(&self) -> kuzushi_core::WorkspaceExportFormat {
        Self::FORMATS[self.format_index]
    }

    pub(crate) fn format_index(&self) -> usize {
        self.format_index
    }

    pub(crate) fn move_format(&mut self, delta: isize) {
        let index = self
            .format_index
            .saturating_add_signed(delta)
            .min(Self::FORMATS.len() - 1);
        if index == self.format_index {
            return;
        }
        self.format_index = index;
        self.choices_saved = false;
        self.receipt = None;
        self.reveal_error = None;
    }

    pub(crate) fn completeness(&self) -> kuzushi_core::WorkspaceExportCompleteness {
        self.completeness
    }

    pub(crate) fn cycle_completeness(&mut self) {
        self.choices_saved = false;
        self.completeness = match self.completeness {
            kuzushi_core::WorkspaceExportCompleteness::All => {
                kuzushi_core::WorkspaceExportCompleteness::Open
            }
            kuzushi_core::WorkspaceExportCompleteness::Open => {
                kuzushi_core::WorkspaceExportCompleteness::Complete
            }
            kuzushi_core::WorkspaceExportCompleteness::Complete => {
                kuzushi_core::WorkspaceExportCompleteness::All
            }
        };
        self.receipt = None;
        self.reveal_error = None;
    }

    pub(crate) fn path_draft(&self) -> &str {
        self.path_edit
            .as_ref()
            .map_or(self.paths[self.format_index].as_str(), FieldEditor::text)
    }

    pub(crate) fn path_edit(&self) -> Option<&FieldEditor> {
        self.path_edit.as_ref()
    }

    pub(crate) fn path_error(&self) -> Option<&str> {
        self.path_error.as_deref()
    }

    pub(crate) fn edit_path_key(&mut self, key: KeyEvent) {
        if let Some(edit) = self.path_edit.as_mut() {
            edit.handle_key(key);
            self.path_error = None;
        }
    }

    pub(crate) fn insert_path_text(&mut self, text: &str) {
        if let Some(edit) = self.path_edit.as_mut() {
            edit.insert(text);
            self.path_error = None;
        }
    }

    pub(crate) fn editing_path(&self) -> bool {
        self.path_edit.is_some()
    }

    pub(crate) fn set_editing_path(&mut self, editing: bool) {
        self.path_edit = editing.then(|| FieldEditor::new(self.paths[self.format_index].clone()));
        self.path_error = None;
    }

    pub(crate) fn save_path_edit(&mut self) {
        let Some(edit) = self.path_edit.as_ref() else {
            return;
        };
        if let Some(error) = path_validation_error(edit.text()) {
            self.path_error = Some(error.to_string());
            return;
        }
        if self.paths[self.format_index] != edit.text() {
            self.choices_saved = false;
        }
        self.paths[self.format_index] = edit.text().to_string();
        self.path_edit = None;
        self.path_error = None;
        self.receipt = None;
        self.reveal_error = None;
    }

    pub(crate) fn set_origin(&mut self, origin: ReportOrigin) {
        self.origin = Some(origin);
    }

    pub(crate) fn take_origin(&mut self) -> Option<ReportOrigin> {
        self.origin.take()
    }

    pub(crate) fn receipt(&self) -> Option<&ReportReceipt> {
        self.receipt.as_ref()
    }

    pub(crate) fn set_receipt(&mut self, receipt: ReportReceipt) {
        self.receipt = Some(receipt);
        self.reveal_error = None;
    }

    pub(crate) fn reveal_error(&self) -> Option<&str> {
        self.reveal_error.as_deref()
    }

    pub(crate) fn set_reveal_error(&mut self, error: Option<String>) {
        self.reveal_error = error;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ReportStudyRef {
    pub(crate) campaign_id: String,
    pub(crate) plan_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReportOrigin {
    pub(crate) view: crate::app::ShellView,
    pub(crate) input_mode: crate::app::InputMode,
}

fn default_report_path(format: kuzushi_core::WorkspaceExportFormat) -> &'static str {
    match format {
        kuzushi_core::WorkspaceExportFormat::Sarif => ".kuzushi/reports/report.sarif",
        kuzushi_core::WorkspaceExportFormat::MarkdownBundle => ".kuzushi/reports/report/",
        kuzushi_core::WorkspaceExportFormat::Jsonl => ".kuzushi/reports/findings.jsonl",
        kuzushi_core::WorkspaceExportFormat::Json => ".kuzushi/reports/findings.json",
        kuzushi_core::WorkspaceExportFormat::Csv => ".kuzushi/reports/findings.csv",
        kuzushi_core::WorkspaceExportFormat::VulnFindings => ".kuzushi/reports/VULN-FINDINGS.json",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportReceipt {
    pub(crate) format: kuzushi_core::WorkspaceExportFormat,
    pub(crate) completeness: kuzushi_core::WorkspaceExportCompleteness,
    pub(crate) count: Option<usize>,
    pub(crate) absolute_path: Option<PathBuf>,
    pub(crate) investigation_receipt_path: Option<PathBuf>,
    pub(crate) error: Option<String>,
    pub(crate) timestamp: String,
}

fn path_validation_error(text: &str) -> Option<&'static str> {
    if text.trim().is_empty() {
        return Some("Enter a destination path.");
    }
    text.chars()
        .any(char::is_control)
        .then_some("Use one path without line breaks or control characters.")
}

#[cfg(test)]
mod tests;
