use super::*;
use std::sync::Arc;
use std::thread::JoinHandle;

#[derive(Clone)]
pub(crate) struct ExportRequest {
    pub(super) export: ReportExport,
    pub(super) review_yield: Option<kuzushi_core::ReviewYieldExportProvenance>,
    pub(super) identity_fold: kuzushi_core::findings::IdentityFoldPolicy,
    pub(super) selection_epoch: u64,
}

pub(super) trait ReportExporter: std::fmt::Debug + Send + Sync {
    fn export(&self, request: &ExportRequest) -> ReportReceipt;
}

#[derive(Debug)]
pub(super) struct FilesystemExporter;

impl ReportExporter for FilesystemExporter {
    fn export(&self, request: &ExportRequest) -> ReportReceipt {
        let export = &request.export;
        let result = export_findings_for_target(
            export.target.as_ref(),
            &export.output,
            Some(export.format.as_str()),
            Some(export.completeness.as_str()),
            true,
            request.review_yield.clone(),
            request.identity_fold,
            export.campaign_id.as_deref(),
        );
        match result {
            Ok(report) => ReportReceipt {
                format: report.format,
                completeness: export.completeness,
                count: Some(report.count),
                absolute_path: Some(report.output_path),
                investigation_receipt_path: report.investigation_receipt_path,
                error: None,
                timestamp: super::super::effects::effect_timestamp(),
            },
            Err(error) => failed_receipt(export, error.to_string()),
        }
    }
}

fn failed_receipt(export: &ReportExport, error: String) -> ReportReceipt {
    ReportReceipt {
        format: export.format,
        completeness: export.completeness,
        count: None,
        absolute_path: super::super::effects::report_absolute_path(
            export.target.as_ref(),
            &export.output,
        ),
        investigation_receipt_path: None,
        error: Some(error),
        timestamp: super::super::effects::effect_timestamp(),
    }
}

fn stopped_receipt(export: &ReportExport) -> ReportReceipt {
    failed_receipt(
        export,
        "Export worker stopped. Inspect the destination before retrying.".into(),
    )
}

struct PendingExport {
    export: ReportExport,
    selection_epoch: u64,
    handle: JoinHandle<ReportReceipt>,
}

pub(crate) struct ReportExportState {
    pending: Option<PendingExport>,
    pub(super) exporter: Arc<dyn ReportExporter>,
}

impl Default for ReportExportState {
    fn default() -> Self {
        Self {
            pending: None,
            exporter: Arc::new(FilesystemExporter),
        }
    }
}

impl std::fmt::Debug for ReportExportState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReportExportState")
            .field("pending", &self.pending_export())
            .finish()
    }
}

impl ReportExportState {
    pub(crate) fn start(
        &mut self,
        request: ExportRequest,
        wake: Option<TerminalLoopWake>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(self.pending.is_none(), "A report is already exporting");
        let exporter = self.exporter.clone();
        let export = request.export.clone();
        let selection_epoch = request.selection_epoch;
        let handle = std::thread::Builder::new()
            .name("report-export".into())
            .spawn(move || {
                let result = kuzushi_core::recovered_panic::catch(|| exporter.export(&request))
                    .unwrap_or_else(|_| stopped_receipt(&request.export));
                if let Some(wake) = wake {
                    wake.notify();
                }
                result
            })?;
        self.pending = Some(PendingExport {
            export,
            selection_epoch,
            handle,
        });
        Ok(())
    }

    pub(super) fn pending_export(&self) -> Option<(&ReportExport, u64)> {
        self.pending
            .as_ref()
            .map(|pending| (&pending.export, pending.selection_epoch))
    }

    pub(super) fn take_completed(&mut self) -> Option<(ReportExport, u64, ReportReceipt)> {
        if !self.pending.as_ref()?.handle.is_finished() {
            return None;
        }
        let pending = self.pending.take()?;
        let receipt = pending
            .handle
            .join()
            .unwrap_or_else(|_| stopped_receipt(&pending.export));
        Some((pending.export, pending.selection_epoch, receipt))
    }
}

impl Drop for ReportExportState {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            let _ = pending.handle.join();
        }
    }
}
