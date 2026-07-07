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
mod canonical_run_markers;
mod canonical_recommendations;
mod jsonl_numbering;
mod llm_audit;
mod output_declared_artifacts;
mod run_artifact;
mod run_events;
mod run_failures;
mod run_paths;
mod run_reproducibility_metadata;
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
pub use artifact_manifest::{load_run_artifacts, RunArtifactManifest};
pub use run_artifact::RunArtifact;
pub use run_events::{append_run_event, next_run_event_number, RunEvent};
pub use run_failures::{
    load_run_failure_context, load_run_failures, output_with_run_fallback_context,
    write_run_failures, FailureToLlmContext, RunFailure, RunFailures,
};
pub(crate) use run_failures::run_failure_artifact_path;
pub use run_paths::{latest_run_path, new_run_id, run_artifact_path, run_dir, runs_root};
pub use run_summary_store::{list_run_summaries, load_run_summary, write_run_summary};
pub use running::{
    RunEnvFingerprint, RunHouseRuleFingerprint, RunLlmCallAudit, RunPromptOverrideFingerprint,
    RunSummary, RunTargetGitMetadata, RunTraceStep,
};
pub use tool_run_record::{
    record_tool_run_complete, record_tool_run_failed, record_tool_run_started,
    record_tool_run_started_with_metadata, record_tool_run_started_with_reproducibility,
    tool_run_output_cost_usd, tool_run_output_findings_count, ToolRunRecord,
};
pub use trace_handle::{
    current_parent_step, with_parent_step, BroadcastSink, JsonlSink, ParentScope, TraceHandle,
    TraceSink, TraceStepBuilder,
};
pub use write_run_artifact_json::{
    append_run_trace_step, next_run_trace_step_number, write_run_artifact_json,
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

fn public_run_artifact_spec(
    spec: &crate::artifact_contract::CanonicalRunArtifactSpec,
) -> RunArtifactSpec {
    RunArtifactSpec {
        leaf: spec.leaf,
        label: spec.label,
        kind: spec.kind,
    }
}
