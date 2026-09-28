use super::iac_scan_options::MAX_SUPPORTED_FILE_BYTES;
use super::{
    analyze_dockerfile, analyze_github_actions, analyze_terraform, classify_iac_file,
    IacScanFinding, IacScanKind, IacScanOptions,
};
use crate::scan::engines::coverage_gaps::{CoverageGapKind, CoverageGaps};
use crate::scan::ScanCancellation;
use anyhow::Result;
use std::path::Path;

#[derive(Default)]
pub(super) struct IacScanAccumulator {
    pub findings: Vec<IacScanFinding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub coverage_gaps: CoverageGaps,
}

impl IacScanAccumulator {
    pub fn scan_file(
        &mut self,
        target: &Path,
        file: &Path,
        options: &IacScanOptions,
        cancellation: &ScanCancellation,
    ) -> Result<()> {
        ensure_iac_scan_active(cancellation)?;
        match read_iac_file(file, options) {
            IacFileRead::Analyze(raw) => self.record_iac_analysis(target, file, options, &raw),
            IacFileRead::Skip => self.files_skipped += 1,
            IacFileRead::Unreadable(error) => {
                self.coverage_gaps
                    .record(target, file, CoverageGapKind::File, &error)
            }
        }
        Ok(())
    }

    fn record_iac_analysis(
        &mut self,
        target: &Path,
        file: &Path,
        options: &IacScanOptions,
        raw: &str,
    ) {
        self.files_scanned += 1;
        self.findings
            .extend(analyze_enabled_iac_file(target, file, options, raw));
    }
}

enum IacFileRead {
    Analyze(String),
    Skip,
    Unreadable(std::io::Error),
}

fn ensure_iac_scan_active(cancellation: &ScanCancellation) -> Result<()> {
    if cancellation.is_cancelled() {
        anyhow::bail!("iac-scan scan cancelled");
    }
    Ok(())
}

fn read_iac_file(file: &Path, options: &IacScanOptions) -> IacFileRead {
    let max_bytes =
        usize::try_from(options.max_file_bytes).unwrap_or(MAX_SUPPORTED_FILE_BYTES as usize);
    match crate::bounded_file::read_utf8_text(file, max_bytes) {
        Ok(raw) => IacFileRead::Analyze(raw),
        // Oversized for the configured bound, or not UTF-8 text at all: both
        // are deliberate exclusions the report already counts as skipped.
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => IacFileRead::Skip,
        // Everything else is a failure to read a manifest the walk already
        // selected, so no rule ran against it.
        Err(error) => IacFileRead::Unreadable(error),
    }
}

type IacAnalyzer = fn(&Path, &Path, &str) -> Vec<IacScanFinding>;

const IAC_ANALYZERS: &[(IacScanKind, IacAnalyzer)] = &[
    (IacScanKind::Dockerfile, analyze_dockerfile),
    (IacScanKind::GithubActions, analyze_github_actions),
    (IacScanKind::Terraform, analyze_terraform),
];

fn analyze_enabled_iac_file(
    target: &Path,
    file: &Path,
    options: &IacScanOptions,
    raw: &str,
) -> Vec<IacScanFinding> {
    enabled_iac_file_kind(target, file, options)
        .and_then(|kind| iac_analyzer(kind).map(|analyzer| analyzer(target, file, raw)))
        .unwrap_or_default()
}

fn enabled_iac_file_kind(
    target: &Path,
    file: &Path,
    options: &IacScanOptions,
) -> Option<IacScanKind> {
    classify_iac_file(target, file).filter(|kind| options.kind.includes(*kind))
}

fn iac_analyzer(kind: IacScanKind) -> Option<IacAnalyzer> {
    IAC_ANALYZERS
        .iter()
        .find_map(|(candidate, analyzer)| (*candidate == kind).then_some(*analyzer))
}
