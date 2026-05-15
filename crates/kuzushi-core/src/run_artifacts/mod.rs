use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
pub(crate) use write_run_artifact_json::*;
mod artifact_manifest;
mod canonical_proof;
mod canonical_run_files;
mod canonical_recommendations;
mod llm_audit;
mod module_result_envelope;
mod output_declared_artifacts;
mod run_events;
mod run_failures;
mod run_paths;
mod run_summary_store;
mod running;
#[cfg(test)]
mod tests;
mod tool_run_failure_result;
mod tool_run_record;
mod tool_run_record_events;
mod trace_handle;
mod trace_step_builder;
mod write_run_artifact_json;
mod write_run_artifact_text;

pub(crate) use canonical_run_files::record_canonical_snapshot_artifacts;
pub(crate) use module_result_envelope::normalized_module_result;
pub use artifact_manifest::{load_run_artifacts, RunArtifactManifest};
pub use run_events::{append_run_event, next_run_event_number, RunEvent};
pub use run_failures::{
    load_run_failure_context, load_run_failures, output_with_run_fallback_context,
    write_run_failures, FailureToLlmContext, RunFailure, RunFailures,
};
pub use run_paths::{new_run_id, run_dir, runs_root};
pub use run_summary_store::{list_run_summaries, load_run_summary, write_run_summary};
pub use running::{RunArtifact, RunLlmCallAudit, RunSummary, RunTraceStep};
pub use tool_run_record::{
    record_tool_run_complete, record_tool_run_failed, record_tool_run_started,
    tool_run_output_cost_usd, tool_run_output_findings_count, ToolRunRecord,
};
pub use trace_handle::{
    current_parent_step, BroadcastSink, JsonlSink, ParentScope, TraceHandle, TraceSink,
    TraceStepBuilder,
};
pub use write_run_artifact_json::{
    append_run_trace_step, next_run_trace_step_number, write_run_artifact_json,
};
pub(crate) use write_run_artifact_text::write_run_artifact_text;
