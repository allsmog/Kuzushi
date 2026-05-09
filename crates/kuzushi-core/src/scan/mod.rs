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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use uuid::Uuid;
mod adapters;
pub mod application;
pub mod domain;
pub mod engines;
pub mod infrastructure;
mod subprocess;

#[cfg(test)]
mod tests;

pub use application::{
    default_scan_engines, normalize_semgrep_json, run_scan_engines, run_scan_engines_with_options,
    run_semgrep_scan, scan_engines_for_tasks, ScanRun, ScanRunOptions,
};
pub use domain::{
    CodeqlPersistedRun, CodeqlScanReport, ScanEngine, ScanEngineOutput, SemgrepPersistedRun,
    SemgrepScanReport, SemgrepScanner,
};
#[cfg(test)]
pub(in crate::scan) use engines::codeql::*;
pub use engines::codeql::{
    index_codeql_sarif_as_static_evidence, normalize_codeql_sarif, CodeqlScanner,
};
pub(in crate::scan) use engines::semgrep::*;
pub use subprocess::ScanCancellation;
use subprocess::{
    capture_scanner_process_pipes, child_process_group_id, configure_scanner_process_group,
    configure_scanner_subprocess_env, join_scanner_process_readers, wait_for_scanner_process,
    ProcessOutput,
};
