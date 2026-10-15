use super::*;

use self::agentic_sast::{split_agentic_sast_tasks, AgenticSastReport};
use self::input::{bool_input, parse_sast_severity_filter, parse_sast_tasks, string_input_any};
use crate::capabilities::systems_hunt::SystemsHuntReport;
use crate::carlini_threat_hunt::CarliniThreatHuntReport;
use crate::findings::Finding;
use crate::findings::StaticProofState;
use crate::proof::whitebox_policy::{apply_whitebox_static_sast_policy, WhiteboxStaticPolicy};
use crate::scan::{
    run_native_scan_files_with_cancellation, run_native_scan_with_cancellation,
    scan_engines_for_tasks, select_default_scan_engines_checked, DefaultScanEngineSelection,
    NativeScanReport, ScanEngine, ScanRunOptions,
};
use anyhow::{Context, Result};
pub(in crate::modules) use findings_count::*;
pub(in crate::modules) use from_tasks::*;
pub(in crate::modules) use optional_positive_count::*;
pub(in crate::modules) use prompt_overrides::*;
pub(in crate::modules) use run_sast_verification_and_patch::*;
pub(in crate::modules) use sastpipelinereports::*;
pub(in crate::modules) use scan_threat_model_lease::ScanThreatModelLease;
use serde_json::{json, Value};
pub(in crate::modules) use taint_iris_next_hunt_input::*;
mod agentic_settings;
mod findings_count;
mod from_tasks;
#[cfg(test)]
mod iac_settings_tests;
mod native_inspections;
pub(in crate::modules) use native_inspections::append_inspection_lines;
mod optional_positive_count;
mod prompt_overrides;
mod reconcile_completed_scan;
mod run_sast_scan;
mod run_sast_verification_and_patch;
mod sastpipelinereports;
mod scan_threat_model_lease;
mod scope_guard;
#[cfg(test)]
mod secret_settings_tests;
#[cfg(test)]
mod semgrep_settings_tests;
pub(in crate::modules) use scope_guard::{bind_sast_scope_input, requested_scope_contracts};
#[cfg(test)]
mod context_tests;
#[cfg(test)]
mod native_partial_tests;
#[cfg(all(test, unix))]
mod native_stopped_tests;
mod taint_iris_next_hunt_input;
mod write;
pub(in crate::modules) use run_sast_scan::run_sast_scan_with_registry;

mod accepted_scope;
pub(in crate::modules) use accepted_scope::{
    bind_accepted_sast_scope_input, scope_scan_options, validate_exact_scope_request,
    SastScanOptions,
};
