use super::*;

mod file_scanning;
mod finding_builder;

pub fn scan_for_secrets(
    target: &Path,
    options: &SecretScanOptions,
    cancellation: &ScanCancellation,
) -> Result<SecretScanReport> {
    let root = canonical_directory(target)?;
    let mut tally = SecretScanTally::default();
    let files = selected_files(&root, options, &mut tally.coverage_gaps)?;
    scan_selected_files(&root, files, options, cancellation, &mut tally)?;
    Ok(tally.into_report(&root, options))
}

pub(super) fn scan_for_secrets_in_files(
    root: &Path,
    files: &[String],
    cancellation: &ScanCancellation,
) -> Result<SecretScanReport> {
    scan_exact_files_with_options(root, files, &SecretScanOptions::default(), cancellation)
}

fn scan_exact_files_with_options(
    root: &Path,
    files: &[String],
    options: &SecretScanOptions,
    cancellation: &ScanCancellation,
) -> Result<SecretScanReport> {
    let root = canonical_directory(root)?;
    let paths = crate::scan::resolve_scan_scopes(&root, files)?;
    anyhow::ensure!(
        paths.iter().all(|path| !path.is_directory),
        "exact secret discovery requires regular files"
    );
    let mut tally = SecretScanTally::default();
    let selected_count = paths.len();
    for (index, path) in paths.into_iter().enumerate() {
        if cancellation.is_cancelled() {
            record_exact_gap(
                &mut tally,
                &root,
                &path.path,
                format!(
                    "operator canceled discovery; {} selected files were not scanned",
                    selected_count - index
                ),
            );
            break;
        }
        tally.record_file(&root, &path.path, options);
        if tally.findings.len() >= options.max_findings {
            record_exact_gap(&mut tally, &root, &path.path, format!("finding limit reached; this file may contain further matches and {} selected files were not scanned", selected_count - index - 1));
            break;
        }
    }
    Ok(tally.into_report(&root, options))
}

fn record_exact_gap(tally: &mut SecretScanTally, root: &Path, file: &Path, reason: String) {
    tally.coverage_gaps.record(
        root,
        file,
        CoverageGapKind::File,
        &std::io::Error::other(reason),
    );
}

#[cfg(test)]
mod exact_tests;

fn selected_files(
    root: &Path,
    options: &SecretScanOptions,
    gaps: &mut CoverageGaps,
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files(root, root, options, &mut files, gaps)?;
    Ok(files)
}

fn scan_selected_files(
    root: &Path,
    files: Vec<PathBuf>,
    options: &SecretScanOptions,
    cancellation: &ScanCancellation,
    tally: &mut SecretScanTally,
) -> Result<()> {
    for file_path in files {
        if cancellation.is_cancelled() {
            anyhow::bail!("secret-scan scan cancelled");
        }
        tally.record_file(root, &file_path, options);
        if tally.findings.len() >= options.max_findings {
            break;
        }
    }
    Ok(())
}

/// What one walk found, plus what it could not read. The outcomes are kept
/// apart so a file nobody could open is never counted as one that was clean.
#[derive(Default)]
struct SecretScanTally {
    findings: Vec<SecretScanFinding>,
    files_scanned: usize,
    files_skipped: usize,
    coverage_gaps: CoverageGaps,
}

impl SecretScanTally {
    fn record_file(&mut self, root: &Path, file_path: &Path, options: &SecretScanOptions) {
        match file_scanning::scan_secret_file(root, file_path, options, &mut self.findings) {
            file_scanning::SecretFileScan::Scanned => self.files_scanned += 1,
            file_scanning::SecretFileScan::Skipped => self.files_skipped += 1,
            file_scanning::SecretFileScan::Unreadable(error) => {
                self.coverage_gaps
                    .record(root, file_path, CoverageGapKind::File, &error)
            }
        }
    }

    fn into_report(mut self, root: &Path, options: &SecretScanOptions) -> SecretScanReport {
        if let Some(filter) = &options.severity {
            self.findings
                .retain(|finding| filter.contains(&finding.severity));
        }
        SecretScanReport {
            target: root.display().to_string(),
            findings: self.findings,
            files_scanned: self.files_scanned,
            files_skipped: self.files_skipped,
            coverage_gaps: self.coverage_gaps,
        }
    }
}
