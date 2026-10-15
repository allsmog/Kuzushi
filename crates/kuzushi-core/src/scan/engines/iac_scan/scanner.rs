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

    fn rebind_scoped_finding(&self, finding: &mut Finding, file_path: String) {
        super::output::rebind_core_finding(finding, file_path);
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        let output = iac_scan_engine_output(target, &self.options, cancellation)?;
        output.ensure_empty_result_is_complete()?;
        Ok(output.findings)
    }

    /// The aggregate scan learns about unread paths only through
    /// `scan_errors`; the default implementation would forward findings
    /// alone and let a partially read target report as complete.
    fn scan_artifacts(
        &self,
        target: &Path,
        cancellation: &ScanCancellation,
    ) -> Result<ScanEngineOutput> {
        iac_scan_engine_output(target, &self.options, cancellation)
    }
}

fn iac_scan_engine_output(
    target: &Path,
    options: &IacScanOptions,
    cancellation: &ScanCancellation,
) -> Result<ScanEngineOutput> {
    let report = scan_iac(target, options, cancellation)?;
    Ok(report_engine_output(report))
}

pub(super) fn report_engine_output(report: IacScanReport) -> ScanEngineOutput {
    ScanEngineOutput {
        findings: report
            .findings
            .iter()
            .map(IacScanFinding::to_core_finding)
            .collect(),
        codeql_sarif_documents: Vec::new(),
        scan_errors: report.coverage_gaps.scan_error_lines(),
    }
}

pub fn scan_iac(
    target: &Path,
    options: &IacScanOptions,
    cancellation: &ScanCancellation,
) -> Result<IacScanReport> {
    options.check_limits()?;
    let target = canonical_directory(target)?;
    let mut scan = IacScanAccumulator::default();
    scan.inspection = IacInspection {
        max_entries: options.max_entries,
        max_total_bytes: options.max_total_bytes,
        max_file_bytes: options.max_file_bytes,
        max_depth: super::collect_iac_files::MAX_IAC_DEPTH,
        ..IacInspection::default()
    };
    let files = sorted_iac_files(&target, options, cancellation, &mut scan)?;

    for file in files {
        if let Err(error) = scan.scan_file(&target, &file, options, cancellation) {
            scan.coverage_gaps.record(
                &target,
                &file,
                CoverageGapKind::File,
                &std::io::Error::other(error.to_string()),
            );
            break;
        }
    }

    Ok(IacScanReport {
        target: target.display().to_string(),
        kind: options.kind,
        findings: scan.findings,
        files_scanned: scan.files_scanned,
        files_skipped: scan.files_skipped,
        coverage_gaps: scan.coverage_gaps,
        inspection: scan.inspection,
    })
}

fn sorted_iac_files(
    target: &Path,
    options: &IacScanOptions,
    cancellation: &ScanCancellation,
    scan: &mut IacScanAccumulator,
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_iac_files_bounded(
        target,
        options,
        cancellation,
        &mut files,
        &mut scan.coverage_gaps,
        &mut scan.inspection,
    )?;
    files.sort();
    Ok(files)
}
