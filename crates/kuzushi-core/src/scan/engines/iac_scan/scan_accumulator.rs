use super::{
    analyze_dockerfile, analyze_github_actions, analyze_terraform, classify_iac_file,
    IacInspection, IacScanFinding, IacScanKind, IacScanOptions,
};
use crate::scan::engines::coverage_gaps::{CoverageGapKind, CoverageGaps};
use crate::scan::ScanCancellation;
use anyhow::Result;
use std::io::Read;
use std::path::Path;

#[derive(Default)]
pub(super) struct IacScanAccumulator {
    pub findings: Vec<IacScanFinding>,
    pub files_scanned: usize,
    pub inspected_files: std::collections::BTreeSet<String>,
    pub files_skipped: usize,
    pub coverage_gaps: CoverageGaps,
    pub inspection: IacInspection,
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
        match read_iac_file(target, file, options, &mut self.inspection) {
            IacFileRead::Analyze(raw) => self.record_iac_analysis(target, file, options, &raw),
            IacFileRead::Skip(error) => {
                self.files_skipped += 1;
                self.coverage_gaps
                    .record(target, file, CoverageGapKind::File, &error);
            }
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
        if let Ok(relative) = file.strip_prefix(target) {
            self.inspected_files
                .insert(crate::workspace::inventory::repo_relative(
                    Path::new(""),
                    relative,
                ));
        }
        self.findings
            .extend(analyze_enabled_iac_file(target, file, options, raw));
    }
}

enum IacFileRead {
    Analyze(String),
    Skip(std::io::Error),
    Unreadable(std::io::Error),
}

fn ensure_iac_scan_active(cancellation: &ScanCancellation) -> Result<()> {
    if cancellation.is_cancelled() {
        anyhow::bail!("iac-scan scan cancelled");
    }
    Ok(())
}

fn read_iac_file(
    target: &Path,
    file: &Path,
    options: &IacScanOptions,
    inspection: &mut IacInspection,
) -> IacFileRead {
    match read_iac_text(target, file, options, inspection) {
        Ok(raw) => IacFileRead::Analyze(raw),
        // Keep skipped counts and the exact incomplete-coverage reason.
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => IacFileRead::Skip(error),
        // Everything else is a failure to read a manifest the walk already
        // selected, so no rule ran against it.
        Err(error) => IacFileRead::Unreadable(error),
    }
}

fn read_iac_text(
    target: &Path,
    path: &Path,
    options: &IacScanOptions,
    inspection: &mut IacInspection,
) -> std::io::Result<String> {
    let file = crate::bounded_file::open_regular_file_within(target, path)?;
    if file.metadata()?.len() > options.max_file_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "IaC file exceeds maxFileBytes; no rules ran",
        ));
    }
    let allowance = (options.max_file_bytes + 1).min(
        options
            .max_total_bytes
            .saturating_sub(inspection.bytes_read),
    );
    let mut bytes = Vec::new();
    let result = file.take(allowance).read_to_end(&mut bytes);
    inspection.bytes_read += bytes.len() as u64;
    result?;
    decode_complete_iac_text(bytes, allowance, options.max_file_bytes)
}

fn decode_complete_iac_text(
    bytes: Vec<u8>,
    allowance: u64,
    max_file_bytes: u64,
) -> std::io::Result<String> {
    if bytes.len() as u64 >= allowance || bytes.len() as u64 > max_file_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "IaC read allowance exhausted; complete file not inspected",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
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
