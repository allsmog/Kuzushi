use crate::capabilities::agentic_sast::{collect_agentic_repo_inventory, require_json_object};
use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use crate::whitebox_static::agent_tool_policy_for_input_and_target;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

mod adapters;
mod application;
mod domain;
#[cfg(test)]
mod tests;

pub(crate) use adapters::*;
pub(crate) use application::*;
pub(crate) use domain::*;
