use super::*;

mod file_scanning;
mod finding_builder;

pub fn scan_for_secrets(
    target: &Path,
    options: &SecretScanOptions,
    cancellation: &ScanCancellation,
) -> Result<SecretScanReport> {
    let root = canonical_directory(target)?;
    let mut files = Vec::new();
    collect_files(&root, options, &mut files)?;
    let mut findings = Vec::new();
    let mut files_scanned = 0usize;
    let mut files_skipped = 0usize;

    for file_path in files {
        if cancellation.is_cancelled() {
            anyhow::bail!("secret-scan scan cancelled");
        }

        match file_scanning::scan_secret_file(&root, &file_path, options, &mut findings) {
            file_scanning::SecretFileScan::Scanned => files_scanned += 1,
            file_scanning::SecretFileScan::Skipped => files_skipped += 1,
            file_scanning::SecretFileScan::Ignored => {}
        }
        if findings.len() >= options.max_findings {
            break;
        }
    }

    if let Some(filter) = &options.severity {
        findings.retain(|finding| filter.contains(&finding.severity));
    }

    Ok(SecretScanReport {
        target: root.display().to_string(),
        findings,
        files_scanned,
        files_skipped,
    })
}
