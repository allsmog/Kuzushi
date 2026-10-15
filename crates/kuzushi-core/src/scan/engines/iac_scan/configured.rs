use super::*;
use std::sync::Mutex;

pub(crate) struct ConfiguredIacScanScanner {
    options: IacScanOptions,
    state: Mutex<IacAllowanceState>,
}

struct IacAllowanceState {
    entries_left: usize,
    bytes_left: u64,
    receipts: Vec<Value>,
}

impl ConfiguredIacScanScanner {
    pub(crate) fn new(options: IacScanOptions) -> Self {
        Self {
            state: Mutex::new(IacAllowanceState {
                entries_left: options.max_entries,
                bytes_left: options.max_total_bytes,
                receipts: Vec::new(),
            }),
            options,
        }
    }

    fn inspect(&self, root: &Path, cancellation: &ScanCancellation) -> Result<ScanEngineOutput> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("IaC inspection accounting is unavailable"))?;
        if state.entries_left == 0 || state.bytes_left < 1024 {
            return Ok(state.uninspected_root(root, &self.options));
        }
        let options = IacScanOptions {
            max_entries: state.entries_left,
            max_total_bytes: state.bytes_left,
            ..self.options.clone()
        };
        // Hold the remaining allowance until a complete accounting receipt exists.
        state.entries_left = 0;
        state.bytes_left = 0;
        let report = match scan_iac(root, &options, cancellation) {
            Ok(report) => report,
            Err(error) => {
                state.receipts.push(serde_json::json!({"engine":"iac-scan","target":root,
                    "status":"incomplete","message":error.to_string(),
                    "unresolvedAllowance":{"maxEntries":options.max_entries,"maxTotalBytes":options.max_total_bytes}}));
                return Err(error);
            }
        };
        state.record(&report, &options, &self.options)?;
        Ok(super::scanner::report_engine_output(report))
    }
}

impl IacAllowanceState {
    fn uninspected_root(&mut self, root: &Path, configured: &IacScanOptions) -> ScanEngineOutput {
        let message = "IaC shared inspection allowance exhausted; source root was not inspected";
        self.receipts.push(serde_json::json!({"engine":"iac-scan","target":root,
            "status":"partial","message":message,
            "configuredLimits":{"maxEntries":configured.max_entries,"maxTotalBytes":configured.max_total_bytes},
            "remainingAllowance":{"entries":self.entries_left,"bytes":self.bytes_left}}));
        ScanEngineOutput {
            scan_errors: vec![format!("{}: {message}", root.display())],
            ..Default::default()
        }
    }

    fn record(
        &mut self,
        report: &IacScanReport,
        remaining: &IacScanOptions,
        configured: &IacScanOptions,
    ) -> Result<()> {
        let entries_left = remaining
            .max_entries
            .checked_sub(report.inspection.entries_visited)
            .context("IaC entry allowance exceeded")?;
        let bytes_left = remaining
            .max_total_bytes
            .checked_sub(report.inspection.bytes_read)
            .context("IaC content allowance exceeded")?;
        self.entries_left = entries_left;
        self.bytes_left = bytes_left;
        let receipt = serde_json::json!({"engine":"iac-scan","target":report.target,
            "inspection":report.inspection,"coverageGaps":report.coverage_gaps,
            "configuredLimits":{"maxEntries":configured.max_entries,"maxTotalBytes":configured.max_total_bytes,"maxFileBytes":configured.max_file_bytes},
            "sharedJobAllowance":{"entriesUsed":configured.max_entries-entries_left,"bytesRead":configured.max_total_bytes-bytes_left}});
        self.receipts.push(receipt);
        Ok(())
    }
}

#[cfg(test)]
mod tests;

impl ScanEngine for ConfiguredIacScanScanner {
    fn id(&self) -> &'static str {
        "iac-scan"
    }
    fn rebind_scoped_finding(&self, finding: &mut Finding, file_path: String) {
        super::output::rebind_core_finding(finding, file_path);
    }
    fn inspection_receipts(&self) -> Vec<Value> {
        self.state
            .lock()
            .map(|state| state.receipts.clone())
            .unwrap_or_else(|_| {
                vec![serde_json::json!({"engine":"iac-scan","status":"unavailable"})]
            })
    }
    fn scan(&self, root: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        let output = self.inspect(root, cancellation)?;
        output.ensure_empty_result_is_complete()?;
        Ok(output.findings)
    }
    fn scan_artifacts(
        &self,
        root: &Path,
        cancellation: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        self.inspect(root, cancellation)
    }
}
