use super::*;

pub trait ScanEngine: Send + Sync {
    fn id(&self) -> &'static str;
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
}

impl ScanEngineOutput {
    pub fn from_findings(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            codeql_sarif_documents: Vec::new(),
        }
    }
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
            config: vec!["auto".to_string()],
        }
    }
}
