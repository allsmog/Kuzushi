use super::*;

impl ScanEngine for SecretScanScanner {
    fn id(&self) -> &'static str {
        "secret-scan"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        Ok(secret_scan_engine_output(target, cancellation)?.findings)
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
    Ok(ScanEngineOutput {
        findings: report
            .findings
            .iter()
            .map(SecretScanFinding::to_core_finding)
            .collect(),
        codeql_sarif_documents: Vec::new(),
        scan_errors: report.coverage_gaps.scan_error_lines(),
    })
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
