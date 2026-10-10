use super::*;

mod prepare_scan_workspace;
mod run_scan_engines_with_options;
mod run_semgrep_scan;
mod scan_context;
mod scan_scope;
pub(crate) use scan_context::{
    freeze_scan_context, inspect_scan_context, read_bound_scan_context, selected_scan_context,
};
pub(crate) use scan_scope::{
    normalized_scan_path, require_directory_scope, resolve_scan_scopes, ScanScope,
};

pub use prepare_scan_workspace::{
    prepare_scan_workspace_state, prepare_scan_workspace_state_with_observer,
    ScanWorkspacePreparation,
};
pub use run_scan_engines_with_options::{
    normalize_semgrep_json, run_scan_engines_with_options,
    run_scan_engines_with_options_and_cancellation,
};
pub(crate) use run_scan_engines_with_options::{
    parse_semgrep_report, run_native_scan_files_with_cancellation,
    run_native_scan_with_cancellation, semgrep_error_summaries, semgrep_findings_from_report,
};
#[cfg(test)]
pub(in crate::scan) use run_semgrep_scan::default_scan_engine_selection_for_test;
pub use run_semgrep_scan::{
    default_scan_engines, run_scan_engines, run_semgrep_scan, scan_engines_for_tasks, ScanRun,
    ScanRunOptions,
};
pub(crate) use run_semgrep_scan::{
    select_default_scan_engines_checked, DefaultScanEngineSelection, SkippedDefaultScanEngine,
};
