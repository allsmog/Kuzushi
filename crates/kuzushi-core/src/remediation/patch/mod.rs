pub(crate) use super::patch_process_adapter::PatchProcessControl as PatchCommandControl;
use crate::findings::{
    Finding, FindingReviewGate, PatchAttempt, PatchProvenance, PatchResult, PatchStatus,
    ReviewConfirmation,
};
use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime, RuntimeCost, RuntimeCostReport};
use crate::structured_output::{query_required_structured_json_with_cost, StructuredJsonContract};
use anyhow::{Context, Result};
pub use apply_reviewed_patch::*;
pub(crate) use build_patch_prompt::*;
pub use detect_validation_plan::*;
pub(crate) use ensure_git_repository::*;
pub(crate) use from_tool_input::*;
pub(crate) use patch_result_to_tool_json::*;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use uuid::Uuid;
pub(crate) use validate_patch::*;
mod apply_reviewed_patch;
mod build_patch_prompt;
mod detect_validation_plan;
mod detector_identity;
mod ensure_git_repository;
mod from_tool_input;
#[cfg(test)]
mod patch_cost_tests;
mod patch_refusal_response;
mod patch_result_to_tool_json;
mod recount_hunks;
mod reverify;
mod run_patch_finding;
mod validate_patch;

pub use run_patch_finding::run_patch_finding;
pub(crate) use reverify::{bind_patch_reverify_input, run_patch_reverify};
