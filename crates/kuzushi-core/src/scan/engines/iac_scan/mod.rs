use crate::findings::{Finding, Severity, StaticProofState};
use crate::scan::engines::coverage_gaps::{CoverageGapKind, CoverageGaps};
use crate::scan::{ScanCancellation, ScanEngine, ScanEngineOutput};
pub(crate) use analyze_dockerfile::*;
pub(crate) use analyze_github_actions::*;
pub(crate) use analyze_terraform::*;
use anyhow::{Context, Result};
pub(crate) use collect_iac_files::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
// The walk itself no longer touches `fs` directly; the test modules do.
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use terraform_block_path::TerraformBlockPath;
mod analyze_dockerfile;
mod analyze_github_actions;
mod analyze_terraform;
mod collect_iac_files;
mod configured;
pub(crate) use configured::ConfiguredIacScanScanner;
mod iac_scan_options;
#[cfg(test)]
mod identity_tests;
mod output;
mod rule_policy;
pub(crate) use rule_policy::enabled_rule_ids;
mod scan_accumulator;
mod scanner;
mod terraform_block_path;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod unread_paths_are_disclosed;

pub use iac_scan_options::IacScanOptions;
pub use iac_scan_options::IacScanReport;
pub use iac_scan_options::{IacInspection, IacScanKind};
pub use output::IacScanFinding;
pub use scanner::scan_iac;
pub use scanner::IacScanScanner;
