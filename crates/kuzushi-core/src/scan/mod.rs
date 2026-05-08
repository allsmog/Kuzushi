use crate::dep_hygiene::{CargoAuditScanner, DepHygieneScanner};
use crate::findings::{Finding, FindingStore, Severity, StaticProofState};
use crate::iac_scan::IacScanScanner;
use crate::secret_scan::SecretScanScanner;
use crate::static_evidence::{
    index_semgrep_findings_as_static_evidence, StaticEvidenceEdge, StaticEvidenceEdgeKind,
    StaticEvidenceIndexReport, StaticEvidenceNode, StaticEvidenceNodeKind, StaticEvidenceStore,
};
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
pub(in crate::scan) use codeql_physical_location::*;
pub(in crate::scan) use extract_codeql_location::*;
pub(in crate::scan) use index_codeql_result_as_static_evidence::*;
pub(in crate::scan) use map_codeql_severity::*;
pub(in crate::scan) use merge_detected_language_output::*;
pub(in crate::scan) use normalize_codeql_result_to_finding::*;
pub(in crate::scan) use semgrep_config::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use uuid::Uuid;
mod subprocess;

mod codeql_physical_location;
mod codeql_scanner;
mod codeql_scanner_model;
mod extract_codeql_location;
mod from_tool_input;
mod hex_value;
mod id;
mod index_codeql_result_as_static_evidence;
mod map_codeql_severity;
mod merge_detected_language_output;
mod normalize_codeql_result_to_finding;
mod normalize_codeql_sarif;
mod run_scan_engines_with_options;
mod run_semgrep_scan;
mod scan_reports;
mod semgrep_config;
pub(in crate::scan) use hex_value::*;
#[cfg(test)]
mod tests;

pub use codeql_scanner_model::CodeqlScanner;
pub use id::ScanEngine;
pub use id::ScanEngineOutput;
pub use id::SemgrepScanner;
pub use normalize_codeql_sarif::index_codeql_sarif_as_static_evidence;
pub use normalize_codeql_sarif::normalize_codeql_sarif;
pub use run_scan_engines_with_options::normalize_semgrep_json;
pub use run_scan_engines_with_options::run_scan_engines_with_options;
pub use run_semgrep_scan::default_scan_engines;
pub use run_semgrep_scan::run_scan_engines;
pub use run_semgrep_scan::run_semgrep_scan;
pub use run_semgrep_scan::scan_engines_for_tasks;
pub use run_semgrep_scan::ScanRun;
pub use run_semgrep_scan::ScanRunOptions;
pub use scan_reports::CodeqlScanReport;
pub use scan_reports::SemgrepPersistedRun;
pub use scan_reports::SemgrepScanReport;
pub use semgrep_config::CodeqlPersistedRun;
pub use subprocess::ScanCancellation;
use subprocess::{
    capture_scanner_process_pipes, child_process_group_id, configure_scanner_process_group,
    configure_scanner_subprocess_env, join_scanner_process_readers, wait_for_scanner_process,
    ProcessOutput,
};
