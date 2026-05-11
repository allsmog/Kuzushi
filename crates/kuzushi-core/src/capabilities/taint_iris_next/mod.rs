use crate::capabilities::agentic_sast::{agentic_severity, is_agentic_context_file};
use crate::capabilities::taint_iris::{sanitize_rule_segment, summarize_taint_path};
use crate::findings::{Finding, Severity, StaticProofState};
use crate::modules::ToolExecutionContext;
use crate::runtime::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentRuntimeOptions, AgentToolPolicy,
};
use crate::whitebox_static::{
    agent_tool_policy_for_input, mark_whitebox_static_findings, whitebox_static_profile_requested,
};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

mod adapters;
mod application;
mod domain;
mod persistence;
#[cfg(test)]
mod tests;

pub(in crate::capabilities::taint_iris_next) use adapters::*;
pub(crate) use application::*;
pub(crate) use domain::*;
pub(in crate::capabilities::taint_iris_next) use persistence::*;
