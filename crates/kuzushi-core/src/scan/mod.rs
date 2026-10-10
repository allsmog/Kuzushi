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
use std::process::{Command, ExitStatus, Stdio};
use uuid::Uuid;
mod adapters;
pub mod application;
pub(crate) use application::{
    freeze_scan_context, inspect_scan_context, read_bound_scan_context, selected_scan_context,
};
pub(crate) use domain::ScanContextDocument;
pub use domain::ScanContextRef;
pub(crate) use infrastructure::{load_scan_context, save_scan_context};
pub mod domain;
pub mod engines;
pub mod infrastructure;
mod subprocess;

/// Privacy-compatible default ruleset for Semgrep-backed security scans.
///
/// Semgrep rejects its special `auto` selector when metrics are disabled. Kuzushi
/// deliberately forces metrics off, so the default must name a concrete pack.
pub(crate) const DEFAULT_SEMGREP_CONFIG: &str = "p/security-audit";

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(in crate::scan) use application::default_scan_engine_selection_for_test;
pub use application::{
    default_scan_engines, normalize_semgrep_json, prepare_scan_workspace_state,
    prepare_scan_workspace_state_with_observer, run_scan_engines, run_scan_engines_with_options,
    run_scan_engines_with_options_and_cancellation, run_semgrep_scan, scan_engines_for_tasks,
    ScanRun, ScanRunOptions, ScanWorkspacePreparation,
};
pub(crate) use application::{
    normalized_scan_path, parse_semgrep_report, require_directory_scope, resolve_scan_scopes,
    run_native_scan_files_with_cancellation, run_native_scan_with_cancellation,
    select_default_scan_engines_checked, semgrep_error_summaries, semgrep_findings_from_report,
    DefaultScanEngineSelection, ScanScope, SkippedDefaultScanEngine,
};
pub(crate) use domain::{
    native_scan_failure, NativeEngineCoverage, NativeEngineDisposition, NativeScanCoverage,
    NativeScanFailure, NativeScanReport,
};
pub use domain::{
    CodeqlPersistedRun, CodeqlScanReport, ScanEngine, ScanEngineOutput, SemgrepPersistedRun,
    SemgrepScanOutcome, SemgrepScanReport, SemgrepScanner,
};
pub(crate) use engines::codeql::index_grounded_codeql_sarif_documents_as_static_evidence;
#[cfg(test)]
pub(in crate::scan) use engines::codeql::*;
pub use engines::codeql::{
    index_codeql_sarif_as_static_evidence, index_codeql_sarif_documents_as_static_evidence,
    normalize_codeql_sarif, CodeqlScanner,
};
pub use engines::exploit_chain::{
    scan_exploit_chains, scan_exploit_chains_with_runtime, ExploitChainReport, ExploitChainScanner,
};
pub use engines::govulncheck::{parse_govulncheck_json, GovulncheckScanner};
pub use engines::license_scan::{
    scan_licenses, scan_licenses_with_options, LicenseScanFinding, LicenseScanOptions,
    LicenseScanReport, LicenseScanScanner,
};
pub use engines::sbom_scan::{
    scan_sbom, SbomComponent, SbomDependencyEdge, SbomLockfile, SbomScanReport,
};
pub(in crate::scan) use engines::semgrep::*;
pub(crate) use subprocess::configure_scanner_process_group;
use subprocess::{
    capture_scanner_process_pipes, configure_scanner_subprocess_env, join_scanner_process_readers,
    wait_for_scanner_process, ProcessOutput, ScannerProcessOutput,
};
pub use subprocess::{
    CancellationDisposition, PreparedProcessGroup, RegisteredChild, ScanCancellation,
};

pub(crate) fn completed_scan_tool_json(output: String, data: Value) -> Value {
    let summary = output_summary(&output);
    crate::module_result::completed_output_result(summary, output, data)
}

pub(crate) fn scan_tool_json_with_coverage(
    output: String,
    data: Value,
    scan_errors: &[String],
) -> Value {
    if scan_errors.is_empty() {
        return completed_scan_tool_json(output, data);
    }
    let summary = output_summary(&output);
    crate::module_result::partial_output_result(
        summary,
        output,
        vec![serde_json::json!(
            "Coverage is incomplete. Read the reported omissions before accepting this scan."
        )],
        data,
    )
}

fn output_summary(output: &str) -> String {
    output
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("scan completed")
        .to_string()
}
