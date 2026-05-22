use crate::capabilities::agentic_sast::{
    agentic_severity, collect_agentic_repo_inventory, findings_array_schema, require_json_object,
};
use crate::findings::{Finding, StaticProofState};
use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use crate::whitebox_static::{
    agent_tool_policy_for_input_and_target, mark_whitebox_static_findings,
    whitebox_static_profile_requested,
};
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use uuid::Uuid;

mod adapters;
mod application;
mod domain;
mod persistence;
#[cfg(test)]
mod tests;

pub(crate) use adapters::*;
pub(crate) use application::*;
pub(crate) use domain::*;
pub(crate) use persistence::*;
