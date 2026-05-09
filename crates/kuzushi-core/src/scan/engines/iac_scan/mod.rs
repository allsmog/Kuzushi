use crate::findings::{Finding, Severity};
use crate::scan::{ScanCancellation, ScanEngine};
pub(crate) use analyze_dockerfile::*;
pub(crate) use analyze_github_actions::*;
pub(crate) use analyze_terraform::*;
use anyhow::{Context, Result};
pub(crate) use collect_iac_files::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
mod analyze_dockerfile;
mod analyze_github_actions;
mod analyze_terraform;
mod collect_iac_files;
mod iac_scan_options;
mod output;
mod scan_accumulator;
mod scanner;
#[cfg(test)]
mod tests;

pub use iac_scan_options::IacScanKind;
pub use iac_scan_options::IacScanOptions;
pub use iac_scan_options::IacScanReport;
pub use output::IacScanFinding;
pub use scanner::scan_iac;
pub use scanner::IacScanScanner;
