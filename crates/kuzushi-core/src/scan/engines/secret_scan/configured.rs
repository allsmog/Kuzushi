//! One prepared scanner shares its allowances across the job's source roots.
use super::*;
use std::sync::Mutex;

pub(crate) struct ConfiguredSecretScanScanner {
    options: SecretScanOptions,
    state: Mutex<InspectionState>,
}

struct InspectionState {
    entries_left: usize,
    bytes_left: u64,
    findings_left: usize,
    receipts: Vec<Value>,
}

impl ConfiguredSecretScanScanner {
    pub(crate) fn new(options: SecretScanOptions) -> Self {
        Self {
            state: Mutex::new(InspectionState {
                entries_left: options.max_entries,
                bytes_left: options.max_total_bytes,
                findings_left: options.max_findings,
                receipts: Vec::new(),
            }),
            options,
        }
    }

    fn inspect(
        &self,
        root: &Path,
        files: Option<&[String]>,
        cancel: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("Secret inspection accounting is unavailable"))?;
        let options = self.remaining_options(&state)?;
        let report = inspect_source(root, files, &options, cancel)?;
        state.record(&report, files, &self.options)?;
        let skipped = report.files_skipped;
        let mut output = super::id::secret_report_output(report);
        if files.is_some() && skipped > 0 {
            output.scan_errors.push(format!(
                "secret-scan skipped {skipped} selected files; those files were not analyzed"
            ));
        }
        Ok(output)
    }

    fn remaining_options(&self, state: &InspectionState) -> Result<SecretScanOptions> {
        anyhow::ensure!(
            state.entries_left > 0,
            "Secret inspection entry allowance reached for this job; no further root was inspected"
        );
        anyhow::ensure!(state.bytes_left > 0, "Secret inspection content allowance reached for this job; no further root was inspected");
        anyhow::ensure!(state.findings_left > 0, "Secret inspection finding allowance reached for this job; no further root was inspected");
        let mut options = self.options.clone();
        options.max_entries = state.entries_left;
        options.max_total_bytes = state.bytes_left;
        options.max_findings = state.findings_left;
        Ok(options)
    }
}

fn inspect_source(
    root: &Path,
    files: Option<&[String]>,
    options: &SecretScanOptions,
    cancel: &ScanCancellation,
) -> Result<SecretScanReport> {
    match files {
        Some(files) => {
            super::scan_for_secrets::scan_exact_files_with_options(root, files, options, cancel)
        }
        None => scan_for_secrets(root, options, cancel),
    }
}

impl InspectionState {
    fn record(
        &mut self,
        report: &SecretScanReport,
        files: Option<&[String]>,
        configured: &SecretScanOptions,
    ) -> Result<()> {
        let inspection = report
            .inspection
            .as_ref()
            .context("Secret inspection returned no accounting receipt")?;
        let entries = inspection
            .traversal_entries
            .unwrap_or_else(|| files.map_or(0, <[String]>::len));
        let entries_left = self
            .entries_left
            .checked_sub(entries)
            .context("Secret entry allowance exceeded")?;
        let bytes_left = self
            .bytes_left
            .checked_sub(inspection.content_bytes_reserved)
            .context("Secret content allowance exceeded")?;
        let findings_left = self
            .findings_left
            .checked_sub(report.findings.len())
            .context("Secret finding allowance exceeded")?;
        self.entries_left = entries_left;
        self.bytes_left = bytes_left;
        self.findings_left = findings_left;
        self.receipts.push(serde_json::json!({"engine":"secret-scan","target":report.target,
            "selection":if files.is_some(){"exact-files"}else{"directory"},"inspection":inspection,"coverageGaps":report.coverage_gaps,
            "configuredLimits":{"maxEntries":configured.max_entries,"maxTotalBytes":configured.max_total_bytes,
                "maxFileBytes":configured.max_file_bytes,"maxFindings":configured.max_findings},
            "totals":{"entriesReserved":configured.max_entries-self.entries_left,
                "contentBytesReserved":configured.max_total_bytes-self.bytes_left,"findings":configured.max_findings-self.findings_left}}));
        Ok(())
    }
}

#[cfg(test)]
mod tests;

impl ScanEngine for ConfiguredSecretScanScanner {
    fn id(&self) -> &'static str {
        "secret-scan"
    }
    fn supports_exact_files(&self) -> bool {
        true
    }
    fn inspection_receipts(&self) -> Vec<Value> {
        match self.state.lock() {
            Ok(state) => state.receipts.clone(),
            Err(_) => vec![
                serde_json::json!({"engine":"secret-scan","status":"unavailable","message":"Secret inspection accounting is unavailable"}),
            ],
        }
    }
    fn scan(&self, root: &Path, cancel: &ScanCancellation) -> Result<Vec<Finding>> {
        let output = self.scan_artifacts(root, cancel)?;
        output.ensure_empty_result_is_complete()?;
        Ok(output.findings)
    }
    fn scan_artifacts(&self, root: &Path, cancel: &ScanCancellation) -> Result<ScanEngineOutput> {
        self.inspect(root, None, cancel)
    }
    fn scan_exact_files(
        &self,
        root: &Path,
        files: &[String],
        cancel: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        self.inspect(root, Some(files), cancel)
    }
}
