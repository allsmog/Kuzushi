use super::BatchOccurrenceReport;
use crate::capabilities::campaign::ScanBatchGateBinding;
use crate::findings::{FindingStore, Severity};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

pub fn derive_batch_gate_binding(
    store: &FindingStore,
    report: &BatchOccurrenceReport,
    threshold: Option<Severity>,
    sarif_path: Option<&Path>,
) -> Result<(ScanBatchGateBinding, usize)> {
    let blocking_keys = blocking_finding_keys(store, report, threshold)?;
    let sarif = sarif_path.map(sarif_receipt).transpose()?;
    let binding = ScanBatchGateBinding {
        logical_terminal_state_sha256: digest(&logical_state(report))?,
        blocking_findings_sha256: digest(&blocking_keys)?,
        sarif_path: sarif.as_ref().map(|(path, _)| path.clone()),
        sarif_sha256: sarif.map(|(_, sha256)| sha256),
    };
    Ok((binding, blocking_keys.len()))
}

fn logical_state(report: &BatchOccurrenceReport) -> impl Serialize + '_ {
    (
        report.planned,
        report.completed,
        report.failed,
        report.pending,
        &report.trials,
    )
}

fn blocking_finding_keys(
    store: &FindingStore,
    report: &BatchOccurrenceReport,
    threshold: Option<Severity>,
) -> Result<BTreeSet<String>> {
    let Some(threshold) = threshold.and_then(severity_rank) else {
        return Ok(BTreeSet::new());
    };
    let mut keys = BTreeSet::new();
    for run_id in report.completed_run_ids() {
        for finding in store.list_findings_for_scan_id(&run_id)? {
            if !finding.suppressed
                && severity_rank(finding.severity).is_some_and(|rank| rank >= threshold)
            {
                keys.insert(report_fold_key(report, &finding.fingerprint)?.to_string());
            }
        }
    }
    Ok(keys)
}

fn report_fold_key<'a>(report: &'a BatchOccurrenceReport, fingerprint: &str) -> Result<&'a str> {
    report
        .rows
        .iter()
        .find(|row| row.fingerprints.iter().any(|value| value == fingerprint))
        .map(|row| row.fold_key.as_str())
        .with_context(|| {
            format!("blocking finding {fingerprint} is absent from batch occurrence rows")
        })
}

fn severity_rank(severity: Severity) -> Option<u8> {
    match severity {
        Severity::Info => Some(0),
        Severity::Low => Some(1),
        Severity::Medium => Some(2),
        Severity::High => Some(3),
        Severity::Critical => Some(4),
        Severity::Unknown => None,
    }
}

fn sarif_receipt(path: &Path) -> Result<(std::path::PathBuf, String)> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect batch SARIF {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "batch SARIF must be a regular non-symlink file: {}",
        path.display()
    );
    let bytes = std::fs::read(path)
        .with_context(|| format!("could not read batch SARIF {}", path.display()))?;
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("could not canonicalize batch SARIF {}", path.display()))?;
    Ok((
        canonical,
        crate::run_lifecycle::sha256_content_digest(&bytes),
    ))
}

fn digest(value: &impl Serialize) -> Result<String> {
    let bytes = crate::review_yield::domain::canonical_json_bytes(value)?;
    Ok(crate::run_lifecycle::sha256_content_digest(&bytes))
}
