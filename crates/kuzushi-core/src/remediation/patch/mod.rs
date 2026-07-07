use crate::findings::{
    Finding, PatchAttempt, PatchResult, PatchStatus, TriageOutcome, TriageVerdict,
};
use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use anyhow::{Context, Result};
pub(crate) use build_patch_prompt::*;
pub(crate) use detect_validation_plan::*;
pub(crate) use ensure_git_repository::*;
pub(crate) use from_tool_input::*;
pub use apply_reviewed_patch::*;
pub(crate) use patch_result_to_tool_json::*;
use serde_json::{json, Map, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use uuid::Uuid;
pub(crate) use validate_patch::*;
mod apply_reviewed_patch;
mod build_patch_prompt;
mod detect_validation_plan;
mod ensure_git_repository;
mod from_tool_input;
mod patch_refusal_response;
mod patch_result_to_tool_json;
mod run_patch_finding;
mod validate_patch;

pub use run_patch_finding::run_patch_finding;
