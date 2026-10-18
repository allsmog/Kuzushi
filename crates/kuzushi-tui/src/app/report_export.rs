//! One explicitly requested export, independent of terminal input and model jobs.
use super::*;
use std::path::Path;

mod worker;
pub(crate) use worker::{ExportRequest, ReportExportState};
use worker::{FilesystemExporter, ReportExporter};

#[cfg(test)]
mod tests;

impl ShellApp {
    pub(super) fn export_report_effect(&mut self, export: ReportExport) {
        if self.refuse_pending_report_export() {
            return;
        }
        self.clear_previous_export_notice();
        if export.target.as_deref() == self.target() {
            self.persist_report_export_choices();
        }
        let request = ExportRequest {
            export,
            review_yield: self.review_yield_export_provenance(),
            identity_fold: self.identity_fold_policy(),
            selection_epoch: self.router.report().selection_epoch(),
        };
        if !self.runtime_state.has_terminal_loop() {
            self.router
                .report_mut()
                .set_receipt(FilesystemExporter.export(&request));
            self.set_shell_view(ShellView::Report);
            self.scroll_to_top();
            return;
        }
        self.start_report_export(request);
    }

    fn start_report_export(&mut self, request: ExportRequest) {
        match self.runtime_state.start_report_export(request) {
            Ok(()) => self.router.report_mut().clear_export_receipt(),
            Err(error) => {
                self.set_error_notice("export", format!("Could not start export: {error}"))
            }
        }
    }

    fn clear_previous_export_notice(&mut self) {
        if self
            .advisory()
            .notice
            .as_ref()
            .is_some_and(|notice| notice.source == "export")
        {
            self.clear_notice();
        }
    }

    pub(crate) fn report_export_pending(&self) -> bool {
        self.runtime_state.report_export.pending_export().is_some()
    }

    pub(crate) fn refuse_pending_report_export(&mut self) -> bool {
        if !self.report_export_pending() {
            return false;
        }
        self.set_warn_notice(
            "export",
            "A report is exporting. This request was not queued.",
        );
        true
    }

    pub(crate) fn report_export_destination(&self) -> Option<&Path> {
        let (export, epoch) = self.runtime_state.report_export.pending_export()?;
        self.report_export_selection_matches(export, epoch)
            .then_some(export.output.as_path())
    }

    pub(crate) fn report_export_description(&self) -> Option<String> {
        let (export, _) = self.runtime_state.report_export.pending_export()?;
        Some(format!(
            "Exporting {} to {}. Reading and navigation remain available.",
            export.format.as_str(),
            export.output.display()
        ))
    }

    fn report_export_selection_matches(&self, export: &ReportExport, epoch: u64) -> bool {
        let route = self.router.report();
        export.target.as_deref() == self.target()
            && export.format == route.format()
            && export.completeness == route.completeness()
            && export.output == Path::new(route.path_draft())
            && epoch == route.selection_epoch()
    }

    pub(crate) fn apply_report_export_result(&mut self) -> bool {
        let Some((export, epoch, receipt)) = self.runtime_state.report_export.take_completed()
        else {
            return false;
        };
        let path = receipt.absolute_path.as_deref().unwrap_or(&export.output);
        match &receipt.error {
            Some(error) => self.set_error_notice(
                "export",
                format!("Export to {} failed: {error}", path.display()),
            ),
            None => self.set_success_notice(
                "export",
                format!("Exported {} to {}", export.format.as_str(), path.display()),
            ),
        }
        if self.report_export_selection_matches(&export, epoch) {
            self.router.report_mut().set_receipt(receipt);
        }
        true
    }
}
