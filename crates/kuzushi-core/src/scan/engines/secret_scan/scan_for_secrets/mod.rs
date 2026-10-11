use super::*;

mod content_budget;
mod file_scanning;
mod finding_builder;
use content_budget::ContentBudget;

pub fn scan_for_secrets(
    target: &Path,
    options: &SecretScanOptions,
    cancellation: &ScanCancellation,
) -> Result<SecretScanReport> {
    let root = canonical_directory(target)?;
    validate_inspection_limits(options)?;
    let mut tally = SecretScanTally::default();
    let mut files = Vec::new();
    tally.traversal_entries = Some(super::traversal::collect(
        &root,
        &root,
        options,
        cancellation,
        &mut files,
        &mut tally.coverage_gaps,
    )?);
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

pub(super) fn scan_exact_files_with_options(
    root: &Path,
    files: &[String],
    options: &SecretScanOptions,
    cancellation: &ScanCancellation,
) -> Result<SecretScanReport> {
    let root = canonical_directory(root)?;
    validate_inspection_limits(options)?;
    anyhow::ensure!(
        files.len() <= options.max_entries,
        "exact file membership exceeds the configured entry allowance"
    );
    let paths = crate::scan::resolve_scan_scopes(&root, files)?;
    anyhow::ensure!(
        paths.iter().all(|path| !path.is_directory),
        "exact secret discovery requires regular files"
    );
    let mut tally = SecretScanTally::default();
    let files = paths.into_iter().map(|path| path.path).collect();
    scan_selected_files(&root, files, options, cancellation, &mut tally)?;
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
#[cfg(test)]
mod limit_tests;

fn scan_selected_files(
    root: &Path,
    files: Vec<PathBuf>,
    options: &SecretScanOptions,
    cancellation: &ScanCancellation,
    tally: &mut SecretScanTally,
) -> Result<()> {
    let selected_count = files.len();
    let mut budget = ContentBudget::new(options.max_total_bytes);
    for (index, file_path) in files.into_iter().enumerate() {
        if !scan_next_file(
            root,
            &file_path,
            options,
            cancellation,
            tally,
            &mut budget,
            selected_count - index,
        ) {
            break;
        }
    }
    tally.content_bytes_reserved = budget.reserved;
    Ok(())
}

fn scan_next_file(
    root: &Path,
    file: &Path,
    options: &SecretScanOptions,
    cancellation: &ScanCancellation,
    tally: &mut SecretScanTally,
    budget: &mut ContentBudget,
    remaining: usize,
) -> bool {
    if cancellation.is_cancelled() {
        record_exact_gap(
            tally,
            root,
            file,
            format!("operator canceled discovery; {remaining} selected files were not scanned"),
        );
        return false;
    }
    if !tally.record_file(root, file, options, budget) {
        return false;
    }
    if tally.findings.len() >= options.max_findings {
        record_exact_gap(tally, root, file, format!("finding limit reached; this file may contain further matches and {} selected files were not scanned", remaining - 1));
        return false;
    }
    true
}

/// What one walk found, plus what it could not read. The outcomes are kept
/// apart so a file nobody could open is never counted as one that was clean.
#[derive(Default)]
struct SecretScanTally {
    findings: Vec<SecretScanFinding>,
    files_scanned: usize,
    files_skipped: usize,
    coverage_gaps: CoverageGaps,
    traversal_entries: Option<usize>,
    content_bytes_reserved: u64,
}

impl SecretScanTally {
    fn record_file(
        &mut self,
        root: &Path,
        file_path: &Path,
        options: &SecretScanOptions,
        budget: &mut ContentBudget,
    ) -> bool {
        match file_scanning::scan_secret_file(root, file_path, options, budget, &mut self.findings)
        {
            file_scanning::SecretFileScan::Scanned => {
                self.files_scanned += 1;
                true
            }
            file_scanning::SecretFileScan::Skipped => {
                self.files_skipped += 1;
                true
            }
            file_scanning::SecretFileScan::Unreadable(gap) => {
                self.files_skipped += usize::from(gap.skipped);
                self.coverage_gaps
                    .record(root, file_path, CoverageGapKind::File, &gap.error);
                !gap.halt
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
            inspection: Some(SecretScanInspection {
                schema_version: 1,
                traversal_entries: self.traversal_entries,
                content_bytes_reserved: self.content_bytes_reserved,
                max_entries: options.max_entries,
                max_file_bytes: options.max_file_bytes,
                max_total_bytes: options.max_total_bytes,
                max_findings: options.max_findings,
                excluded_directories: options.exclude_dirs.iter().cloned().collect(),
                excluded_extensions: options.binary_exts.iter().cloned().collect(),
            }),
        }
    }
}

fn validate_inspection_limits(options: &SecretScanOptions) -> Result<()> {
    anyhow::ensure!(
        (1..=100_000).contains(&options.max_entries),
        "maxEntries must be from 1 to 100000"
    );
    anyhow::ensure!(
        (1..=536_870_912).contains(&options.max_total_bytes),
        "maxTotalBytes must be positive and at most 536870912"
    );
    Ok(())
}
