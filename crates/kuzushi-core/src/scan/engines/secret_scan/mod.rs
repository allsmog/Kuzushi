use crate::findings::{Finding, Severity, StaticProofState};
use crate::scan::engines::coverage_gaps::{CoverageGapKind, CoverageGaps};
use crate::scan::{ScanCancellation, ScanEngine, ScanEngineOutput};
use anyhow::{Context, Result};
pub(crate) use assignment_detection::*;
pub(crate) use canonical_directory::*;
pub(crate) use classify_token::*;
pub(crate) use id::*;
pub(crate) use secret_scan_report::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(test)]
mod applies_size_binary_and_severity_filters;
mod assignment_detection;
#[cfg(test)]
mod cancellation_stops_native_scan;
mod canonical_directory;
mod classify_token;
mod configured;
pub(crate) use configured::ConfiguredSecretScanScanner;
mod id;
mod is_token_char;
mod output;
mod scan_for_secrets;
mod scanner_options;
mod secret_scan_report;
mod traversal;
pub(in crate::scan::engines::secret_scan) use is_token_char::*;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod unread_paths_are_disclosed;

pub use output::SecretScanFinding;
pub use output::SecretSeverity;
pub use scan_for_secrets::scan_for_secrets;
pub use scanner_options::SecretScanOptions;
pub use scanner_options::SecretScanScanner;
pub(crate) use scanner_options::MAX_SUPPORTED_FILE_BYTES;
pub use secret_scan_report::SecretScanInspection;
pub use secret_scan_report::SecretScanReport;
