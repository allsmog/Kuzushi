use super::prelude::*;
use super::*;

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

    'outer: for file_path in files {
        if cancellation.is_cancelled() {
            anyhow::bail!("secret-scan scan cancelled");
        }

        if is_binary_extension(&file_path, &options.binary_exts) {
            files_skipped += 1;
            continue;
        }

        let Ok(metadata) = fs::metadata(&file_path) else {
            continue;
        };
        if metadata.len() > options.max_file_bytes {
            files_skipped += 1;
            continue;
        }

        let Ok(bytes) = fs::read(&file_path) else {
            continue;
        };
        if is_likely_binary(&bytes) {
            files_skipped += 1;
            continue;
        }
        files_scanned += 1;

        let text = String::from_utf8_lossy(&bytes);
        let rel_path = file_path
            .strip_prefix(&root)
            .unwrap_or(&file_path)
            .display()
            .to_string();
        for hit in detect_secrets_in_text(&text) {
            let location = locate_match(&text, hit.index);
            let fingerprint = fingerprint_for(
                &root,
                hit.detector.id,
                &rel_path,
                location.line,
                &hit.matched,
            );
            let redacted = redact_secret(&hit.captured_secret);
            let evidence_line = location
                .line_text
                .replacen(&hit.captured_secret, &redacted, 1)
                .trim()
                .to_string();
            let severity = hit.detector.severity;
            findings.push(SecretScanFinding {
                task_id: "secret-scan".to_string(),
                fingerprint,
                rule_id: format!("secret-scan/{}", hit.detector.id),
                file_path: rel_path.clone(),
                start_line: location.line,
                severity,
                message: format!("{}: {}", hit.detector.name, hit.detector.description),
                evidence: format!("{}:{}: {}", rel_path, location.line, evidence_line),
                scanner_confidence: if hit.detector.entropy_threshold.is_some() {
                    "MEDIUM".to_string()
                } else {
                    "HIGH".to_string()
                },
                subcategory: vec!["secret".to_string()],
                likelihood: if severity == SecretSeverity::Error {
                    "HIGH".to_string()
                } else {
                    "MEDIUM".to_string()
                },
                impact: if severity == SecretSeverity::Error {
                    "HIGH".to_string()
                } else {
                    "MEDIUM".to_string()
                },
                cwe: vec![hit.detector.cwe.to_string()],
                score: match severity {
                    SecretSeverity::Error => 30,
                    SecretSeverity::Warning => 20,
                    SecretSeverity::Info => 10,
                },
            });

            if findings.len() >= options.max_findings {
                break 'outer;
            }
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
