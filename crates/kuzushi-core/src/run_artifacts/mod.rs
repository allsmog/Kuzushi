use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
pub(crate) use write_run_artifact_json::*;
mod artifact_manifest;
mod canonical_run_files;
mod canonical_run_markers;
mod jsonl_append;
mod jsonl_numbering;
mod llm_audit;
mod output_declared_artifacts;
mod process_identity;
mod run_artifact;
mod run_artifact_reader;
mod run_events;
mod run_failures;
mod run_history_index;
mod run_ledger;
mod run_paths;
mod run_reproducibility_metadata;
mod run_result_summary;
mod run_summary_store;
mod running;
mod scan_stage;
#[cfg(test)]
mod tests;
mod tool_output_cost;
mod tool_run_failure_result;
mod tool_run_record;
mod tool_run_record_events;
mod trace_cost;
mod trace_handle;
mod trace_step_builder;
mod write_run_artifact_json;
mod write_run_artifact_text;

pub(crate) use artifact_manifest::record_run_artifact;
pub use artifact_manifest::{load_run_artifacts, RunArtifactManifest};
pub(crate) use jsonl_append::append_run_artifact_jsonl_value;
pub use run_artifact::RunArtifact;
pub use run_artifact_reader::{
    read_run_artifact_bytes, read_run_artifact_text, resolve_run_artifact_path,
    RunArtifactBytesRead, RunArtifactRead, RunArtifactTextRead, MAX_RUN_ARTIFACT_READ_BYTES,
};
pub(crate) use run_events::append_compat_run_item_events;
pub use run_events::{
    append_run_event, load_run_events, next_run_event_number, RunEvent, RunEventRead,
    RunInteractionAudit,
};
pub(crate) use run_failures::run_failure_artifact_path;
pub use run_failures::{
    load_run_failure_context, load_run_failures, output_with_run_fallback_context,
    write_run_failures, FailureToLlmContext, RunFailure, RunFailures,
};
pub use run_history_index::{RunHistoryCursor, RunHistoryPageInfo};
pub(crate) use run_paths::{
    checked_latest_run_path, checked_legacy_run_history_index_path, checked_run_artifact_path,
    checked_run_history_dirty_path, checked_run_history_index_path, checked_runs_root,
    ensure_run_artifact_parent, ensure_run_dir,
};
pub use run_paths::{
    latest_run_path, new_run_id, run_artifact_path, run_dir, runs_root, ArtifactPath, RunId,
};
pub(crate) use run_result_summary::load_correlated_run_result_value;
pub use run_result_summary::{
    load_correlated_run_result_summary, load_run_result_summary, RunResultSummary,
};
pub(crate) use run_summary_store::{list_current_run_summary_prefix, CurrentRunSummaryPrefix};
pub use run_summary_store::{
    list_recent_run_summary_entries, list_run_summaries, list_run_summary_entries,
    list_run_summary_entries_cursor_page, list_run_summary_entries_page, load_run_summary,
    read_latest_run_pointer, repair_latest_run_pointer, write_run_summary, LatestRunPointerIssue,
    LatestRunPointerState, RunSummaryEntriesCursorPage, RunSummaryEntry, RunSummaryEntryState,
    RunSummaryIssue,
};
pub use running::{
    RunEnvFingerprint, RunHouseRuleFingerprint, RunLlmCallAudit, RunPromptOverrideFingerprint,
    RunSummary, RunTargetGitMetadata, RunTraceStep,
};
pub use scan_stage::{
    load_scan_stage_data, PhaseStageOutcome, PhaseStageReceipt, ScanArtifactDelta,
    ScanEngineStageOutcome, ScanFindingDelta, ScanStageCost, ScanStageData, ScanStageEngine,
    ScanStagePlan, ScanStageScope, SAST_PHASE_STAGES_JSONL_FILE,
};
pub use tool_output_cost::tool_run_output_cost_report;
pub(crate) use tool_run_record::terminal_result_digest;
pub use tool_run_record::{
    record_tool_run_canceled, record_tool_run_complete, record_tool_run_failed,
    record_tool_run_interrupted, record_tool_run_refused, record_tool_run_started,
    record_tool_run_started_with_metadata, record_tool_run_started_with_reproducibility,
    tool_run_output_cost_usd, tool_run_output_findings_count, tool_run_terminal_digest,
    try_record_tool_run_canceled, try_record_tool_run_canceled_observed,
    try_record_tool_run_canceled_settled,
    try_record_tool_run_complete, try_record_tool_run_complete_observed,
    try_record_tool_run_complete_settled, try_record_tool_run_failed,
    try_record_tool_run_failed_observed, try_record_tool_run_failed_observed_with_execution,
    try_record_tool_run_failed_settled, try_record_tool_run_interrupted,
    try_record_tool_run_interrupted_observed, try_record_tool_run_interrupted_settled,
    try_record_tool_run_refused, try_record_tool_run_refused_observed,
    try_record_tool_run_refused_settled, try_record_tool_run_started_with_reproducibility,
    ToolRunRecord,
};
pub use trace_cost::{
    reconcile_terminal_cost_reports, terminal_model_call_cost_report, trace_cost_report,
};
pub use trace_handle::{
    current_parent_step, with_parent_step, BroadcastSink, JsonlSink, ParentScope, TraceHandle,
    TraceSink, TraceStepBuilder,
};
pub use write_run_artifact_json::{
    append_run_trace_step, append_run_trace_step_with_next_number, load_run_trace,
    next_run_trace_step_number, write_run_artifact_json, RunTraceRead,
};
pub(crate) use write_run_artifact_text::write_run_artifact_text;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunArtifactSpec {
    pub leaf: &'static str,
    pub label: &'static str,
    pub kind: &'static str,
}

pub fn canonical_run_artifact_specs() -> Vec<RunArtifactSpec> {
    crate::artifact_contract::CANONICAL_RUN_ARTIFACTS
        .iter()
        .map(public_run_artifact_spec)
        .collect()
}

pub fn canonical_run_artifact_spec(leaf: &str) -> Option<RunArtifactSpec> {
    crate::artifact_contract::canonical_run_artifact_spec(leaf).map(public_run_artifact_spec)
}

pub fn tool_result_artifact_spec(leaf: &str) -> Option<RunArtifactSpec> {
    crate::artifact_contract::tool_result_artifact_spec(leaf).map(public_run_artifact_spec)
}

pub fn scan_pipeline_artifact_spec(leaf: &str) -> Option<RunArtifactSpec> {
    crate::artifact_contract::scan_pipeline_artifact_spec(leaf).map(public_run_artifact_spec)
}

fn public_run_artifact_spec(
    spec: &crate::artifact_contract::CanonicalRunArtifactSpec,
) -> RunArtifactSpec {
    RunArtifactSpec {
        leaf: spec.leaf,
        label: spec.label,
        kind: spec.kind,
    }
}
