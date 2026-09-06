use super::*;

pub trait ScanEngine: Send + Sync {
    fn id(&self) -> &'static str;

    fn preflight(&self) -> Result<()> {
        Ok(())
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>>;

    fn scan_artifacts(
        &self,
        target: &Path,
        cancellation: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        Ok(ScanEngineOutput::from_findings(
            self.scan(target, cancellation)?,
        ))
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ScanEngineOutput {
    pub findings: Vec<Finding>,
    pub codeql_sarif_documents: Vec<String>,
    /// What the engine could not analyze. A run can produce findings while
    /// leaving part of the target unscanned; callers that report scan
    /// completion disclose these gaps instead of implying full coverage.
    pub scan_errors: Vec<String>,
}

impl ScanEngineOutput {
    pub fn from_findings(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            codeql_sarif_documents: Vec::new(),
            scan_errors: Vec::new(),
        }
    }
}

/// Findings plus semgrep's own account of what it failed to scan. A run can
/// exit successfully while skipping files or rules; callers that report scan
/// completion should disclose those gaps instead of implying full coverage.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SemgrepScanOutcome {
    pub findings: Vec<Finding>,
    pub scan_errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SemgrepScanner {
    pub binary: String,
    pub config: Vec<String>,
}

impl Default for SemgrepScanner {
    fn default() -> Self {
        Self {
            binary: "semgrep".to_string(),
            config: vec![DEFAULT_SEMGREP_CONFIG.to_string()],
        }
    }
}

pub(crate) fn scanner_binary_available(binary: &str) -> bool {
    let trimmed = binary.trim();
    if trimmed.is_empty() {
        return false;
    }
    let path = Path::new(trimmed);
    if path.components().count() > 1 {
        return path.is_file();
    }
    crate::process_lookup::executable_on_path(trimmed).is_some()
}
