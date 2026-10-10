use super::bounded_regular_files::{
    collect_regular_files, FileLimitBehavior, RegularFileWalkOptions,
};
use crate::findings::{Finding, Severity, StaticProofState};
use crate::scan::{ScanCancellation, ScanEngine};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
#[cfg(test)]
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

mod license_file;
mod manifest;
mod report;
mod source_header;

use license_file::repository_license_findings;
use manifest::{is_license_manifest, manifest_license, ManifestLicense};
use source_header::source_header_findings;

const MAX_LICENSE_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_LICENSE_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SOURCE_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Default)]
pub struct LicenseScanScanner;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LicenseScanOptions {
    pub require_source_spdx_headers: bool,
}

impl ScanEngine for LicenseScanScanner {
    fn id(&self) -> &'static str {
        "license-scan"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        Ok(scan_licenses(target, cancellation)?
            .findings
            .iter()
            .map(LicenseScanFinding::to_core_finding)
            .collect())
    }
}

pub fn scan_licenses(target: &Path, cancellation: &ScanCancellation) -> Result<LicenseScanReport> {
    scan_licenses_with_options(target, cancellation, LicenseScanOptions::default())
}

pub fn scan_licenses_with_options(
    target: &Path,
    cancellation: &ScanCancellation,
    options: LicenseScanOptions,
) -> Result<LicenseScanReport> {
    ensure_directory(target)?;
    let files = collect_regular_files(target, cancellation, license_walk_options())?.files;
    let mut manifests = files
        .iter()
        .filter(|path| is_license_manifest(path))
        .cloned()
        .collect::<Vec<_>>();
    manifests.sort_by_key(|path| relative_display(target, path));
    let mut findings = manifests
        .iter()
        .filter_map(|path| license_finding(target, path, cancellation).transpose())
        .collect::<Result<Vec<_>>>()?;
    findings.extend(repository_license_findings(
        target,
        &manifests,
        &files,
        cancellation,
    )?);
    findings.extend(source_header_findings(
        target,
        &manifests,
        &files,
        cancellation,
        options.require_source_spdx_headers,
    )?);
    ensure_scan_active(cancellation)?;
    Ok(LicenseScanReport {
        target: target.display().to_string(),
        manifests_scanned: manifests.len(),
        findings,
    })
}

fn ensure_directory(target: &Path) -> Result<()> {
    if !target.exists() {
        anyhow::bail!("license-scan: target does not exist: {}", target.display());
    }
    if !target.is_dir() {
        anyhow::bail!(
            "license-scan: target is not a directory: {}",
            target.display()
        );
    }
    Ok(())
}

fn license_walk_options() -> RegularFileWalkOptions {
    RegularFileWalkOptions {
        operation: "license-scan",
        max_entries: 100_000,
        max_files: 50_000,
        max_depth: 64,
        file_limit: FileLimitBehavior::Error,
        ignored_dir,
    }
}

fn ensure_scan_active(cancellation: &ScanCancellation) -> Result<()> {
    cancellation.wait_if_paused();
    anyhow::ensure!(!cancellation.is_cancelled(), "license-scan scan cancelled");
    Ok(())
}

fn ignored_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                ".git" | ".kuzushi" | "node_modules" | "vendor" | "target" | "dist" | "build"
            )
        })
}

fn license_finding(
    target: &Path,
    path: &Path,
    cancellation: &ScanCancellation,
) -> Result<Option<LicenseScanFinding>> {
    ensure_scan_active(cancellation)?;
    let text = crate::bounded_file::read_utf8_text_within(target, path, MAX_LICENSE_MANIFEST_BYTES)
        .with_context(|| format!("license-scan: read {}", path.display()))?;
    match manifest_license(path, &text)? {
        ManifestLicense::Skip => Ok(None),
        ManifestLicense::Missing => Ok(Some(missing_license_finding(target, path))),
        ManifestLicense::Declared(license) => {
            Ok(risky_license(&license)
                .map(|risk| risky_license_finding(target, path, &license, risk)))
        }
    }
}

fn missing_license_finding(target: &Path, path: &Path) -> LicenseScanFinding {
    LicenseScanFinding::new(
        target,
        path,
        "license-scan/missing-license",
        Severity::Low,
        "Package manifest does not declare a license",
        "license field missing",
        None,
    )
}

fn risky_license_finding(
    target: &Path,
    path: &Path,
    license: &str,
    risk: LicenseRisk,
) -> LicenseScanFinding {
    LicenseScanFinding::new(
        target,
        path,
        risk.rule_id(),
        risk.severity(),
        risk.message(),
        format!("license = {license}"),
        Some(license.to_string()),
    )
}

fn risky_license(license: &str) -> Option<LicenseRisk> {
    let normalized = license.to_ascii_lowercase();
    if weak_copyleft_license(&normalized) {
        return Some(LicenseRisk::WeakCopyleft);
    }
    if strong_copyleft_license(&normalized) {
        return Some(LicenseRisk::StrongCopyleft);
    }
    None
}

fn weak_copyleft_license(normalized: &str) -> bool {
    license_contains_token(normalized, "lgpl")
        || normalized.contains("lesser general public license")
        || license_contains_token(normalized, "mpl")
        || normalized.contains("mozilla public license")
        || license_contains_token(normalized, "epl")
        || normalized.contains("eclipse public license")
        || license_contains_token(normalized, "cddl")
        || normalized.contains("common development and distribution license")
}

fn strong_copyleft_license(normalized: &str) -> bool {
    license_contains_token(normalized, "agpl")
        || license_contains_token(normalized, "gpl")
        || normalized.contains("general public license")
}

fn license_contains_token(normalized: &str, token: &str) -> bool {
    normalized
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|part| part == token)
}

enum LicenseRisk {
    StrongCopyleft,
    WeakCopyleft,
}

impl LicenseRisk {
    fn rule_id(&self) -> &'static str {
        match self {
            Self::StrongCopyleft => "license-scan/strong-copyleft",
            Self::WeakCopyleft => "license-scan/weak-copyleft",
        }
    }

    fn severity(&self) -> Severity {
        match self {
            Self::StrongCopyleft => Severity::Medium,
            Self::WeakCopyleft => Severity::Low,
        }
    }

    fn message(&self) -> &'static str {
        match self {
            Self::StrongCopyleft => "Manifest declares a strong copyleft license",
            Self::WeakCopyleft => "Manifest declares a weak copyleft license",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LicenseScanFinding {
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub severity: Severity,
    pub message: String,
    pub evidence: String,
    pub license: Option<String>,
}

impl LicenseScanFinding {
    fn new(
        target: &Path,
        path: &Path,
        rule_id: &'static str,
        severity: Severity,
        message: impl Into<String>,
        evidence: impl Into<String>,
        license: Option<String>,
    ) -> Self {
        let file_path = relative_display(target, path);
        let message = message.into();
        let evidence = evidence.into();
        Self {
            fingerprint: fingerprint(rule_id, &file_path, &evidence),
            rule_id: rule_id.to_string(),
            file_path,
            start_line: 1,
            severity,
            message,
            evidence,
            license,
        }
    }

    pub fn to_core_finding(&self) -> Finding {
        let mut finding = Finding::new_tool(
            "license-scan",
            self.rule_id.clone(),
            self.file_path.clone(),
            self.start_line,
            Some(self.start_line),
            self.severity,
            format!("{}\nEvidence: {}", self.message, self.evidence),
        );
        finding.fingerprint = self.fingerprint.clone();
        finding.title = self.message.clone();
        finding.set_static_proof_state(StaticProofState::SignalOnly);
        finding
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LicenseScanReport {
    pub target: String,
    pub manifests_scanned: usize,
    pub findings: Vec<LicenseScanFinding>,
}

fn fingerprint(rule_id: &str, file_path: &str, evidence: &str) -> String {
    let mut hasher = DefaultHasher::new();
    (rule_id, file_path, evidence).hash(&mut hasher);
    format!("license-scan:{:016x}", hasher.finish())
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
