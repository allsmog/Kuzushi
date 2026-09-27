use super::*;
use scan_accumulator::IacScanAccumulator;

#[derive(Debug, Clone)]
pub struct IacScanScanner {
    pub options: IacScanOptions,
}

impl Default for IacScanScanner {
    fn default() -> Self {
        Self {
            options: IacScanOptions::default(),
        }
    }
}

impl IacScanScanner {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            options: IacScanOptions::from_tool_input(input)?,
        })
    }
}

impl ScanEngine for IacScanScanner {
    fn id(&self) -> &'static str {
        "iac-scan"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        let report = scan_iac(target, &self.options, cancellation)?;
        Ok(report
            .findings
            .iter()
            .map(IacScanFinding::to_core_finding)
            .collect())
    }
}

pub fn scan_iac(
    target: &Path,
    options: &IacScanOptions,
    cancellation: &ScanCancellation,
) -> Result<IacScanReport> {
    let target = canonical_directory(target)?;
    let mut scan = IacScanAccumulator::default();
    let files = sorted_iac_files(&target, options, &mut scan.coverage_gaps)?;

    for file in files {
        scan.scan_file(&target, &file, options, cancellation)?;
    }

    Ok(IacScanReport {
        target: target.display().to_string(),
        kind: options.kind,
        findings: scan.findings,
        files_scanned: scan.files_scanned,
        files_skipped: scan.files_skipped,
        coverage_gaps: scan.coverage_gaps,
    })
}

fn sorted_iac_files(
    target: &Path,
    options: &IacScanOptions,
    gaps: &mut CoverageGaps,
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_iac_files(target, target, options, &mut files, gaps)?;
    files.sort();
    Ok(files)
}
