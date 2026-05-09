/// Ground-truth Rust supply-chain scanner backed by `cargo audit --json`.
///
/// Mirrors the security-scanner design instinct of preferring deterministic scanner
/// output over LLM-rediscovered manifest patterns. Runs only when the target
/// has a `Cargo.lock` and the `cargo-audit` binary is on PATH; otherwise
/// returns no findings (the legacy text-parse path in `DepHygieneScanner`
/// remains the fallback).

/// Parse a `cargo audit --json` document into core `Finding`s.
///
/// Public for testing and for any future direct-pipe callers (e.g. CI feeding
/// pre-captured advisories into the findings store without re-running cargo).
use crate::findings::{Finding, Severity};
use crate::scan::{ScanCancellation, ScanEngine};
pub(crate) use analyze_package_json::*;
pub(crate) use analyze_pyproject_toml::*;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
pub(crate) use textual_cvss_severity::*;
mod analyze_package_json;
mod analyze_pep508;
mod analyze_pyproject_toml;
mod dep_hygiene_scanners;
mod id;
mod output;
mod textual_cvss_severity;
pub(in crate::scan::engines::dep_hygiene) use analyze_pep508::*;
#[cfg(test)]
mod tests;

pub use dep_hygiene_scanners::CargoAuditScanner;
pub use dep_hygiene_scanners::DepHygieneScanner;
pub use dep_hygiene_scanners::DepHygieneSeverity;
pub use id::parse_cargo_audit_output;
pub use output::DepHygieneFinding;
pub use output::DepHygieneReport;
pub use textual_cvss_severity::analyze_manifest;
pub use textual_cvss_severity::check_dependency_hygiene;
pub use textual_cvss_severity::ManifestKind;
