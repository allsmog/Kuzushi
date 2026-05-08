use super::{
    analyze_dockerfile, analyze_github_actions, analyze_terraform, classify_iac_file,
    IacScanFinding, IacScanKind, IacScanOptions,
};
use crate::scan::ScanCancellation;
use anyhow::Result;
use std::fs;
use std::path::Path;

#[derive(Default)]
pub(super) struct IacScanAccumulator {
    pub findings: Vec<IacScanFinding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
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
}

fn ensure_iac_scan_active(cancellation: &ScanCancellation) -> Result<()> {
    if cancellation.is_cancelled() {
        anyhow::bail!("iac-scan scan cancelled");
    }
    Ok(())
}

fn read_iac_file(file: &Path, options: &IacScanOptions) -> IacFileRead {
    fs::metadata(file)
        .ok()
        .filter(|metadata| metadata.len() <= options.max_file_bytes)
        .and_then(|_| fs::read_to_string(file).ok())
        .map(IacFileRead::Analyze)
        .unwrap_or(IacFileRead::Skip)
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
