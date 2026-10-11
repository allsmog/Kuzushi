use super::*;

impl ScanEngine for SecretScanScanner {
    fn id(&self) -> &'static str {
        "secret-scan"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        let output = secret_scan_engine_output(target, cancellation)?;
        output.ensure_empty_result_is_complete()?;
        Ok(output.findings)
    }

    fn supports_exact_files(&self) -> bool {
        true
    }

    fn scan_exact_files(
        &self,
        root: &Path,
        files: &[String],
        cancellation: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        let report = super::scan_for_secrets::scan_for_secrets_in_files(root, files, cancellation)?;
        let skipped = report.files_skipped;
        let mut output = secret_report_output(report);
        if skipped > 0 {
            output.scan_errors.push(format!("secret-scan skipped {skipped} selected files because of file size or binary content; those files were not analyzed"));
        }
        Ok(output)
    }

    /// The aggregate scan learns about unread paths only through
    /// `scan_errors`; the default implementation would forward findings
    /// alone and let a partially read target report as complete.
    fn scan_artifacts(
        &self,
        target: &Path,
        cancellation: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        secret_scan_engine_output(target, cancellation)
    }
}

fn secret_scan_engine_output(
    target: &Path,
    cancellation: &ScanCancellation,
) -> Result<ScanEngineOutput> {
    let report = scan_for_secrets(target, &SecretScanOptions::default(), cancellation)?;
    Ok(secret_report_output(report))
}

pub(super) fn secret_report_output(report: SecretScanReport) -> ScanEngineOutput {
    ScanEngineOutput {
        findings: report
            .findings
            .iter()
            .map(SecretScanFinding::to_core_finding)
            .collect(),
        codeql_sarif_documents: Vec::new(),
        scan_errors: report.coverage_gaps.scan_error_lines(),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Detector {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) severity: SecretSeverity,
    pub(crate) entropy_threshold: Option<f64>,
    pub(crate) cwe: &'static str,
    pub(crate) description: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) struct SecretHit {
    pub(crate) detector: Detector,
    pub(crate) matched: String,
    pub(crate) captured_secret: String,
    pub(crate) index: usize,
}
