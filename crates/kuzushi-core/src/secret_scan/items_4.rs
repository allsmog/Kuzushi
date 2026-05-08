use super::prelude::*;
use super::*;

impl ScanEngine for SecretScanScanner {
    fn id(&self) -> &'static str {
        "secret-scan"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        let report = scan_for_secrets(target, &SecretScanOptions::default(), cancellation)?;
        Ok(report
            .findings
            .iter()
            .map(SecretScanFinding::to_core_finding)
            .collect())
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
