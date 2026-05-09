use crate::capabilities::agentic_sast::collect_agentic_repo_inventory;
use crate::capabilities::plugin_adapters::adapters::{
    positive_usize_input, resolve_required_plugin_root, resolve_tool_model, resolve_tool_target,
    string_array_or_csv_input, string_input_any,
};
use crate::capabilities::plugin_adapters::domain::PluginAdapterSpec;
use crate::findings::{
    normalize_agent_json_findings, persist_tool_findings, render_generic_findings_output, Finding,
    GenericPersistedRun,
};
use crate::modules::ToolExecutionContext;
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) use list_shinsa_frameworks::list_shinsa_frameworks;
pub(crate) use list_tob_skills::{list_tob_skills, validate_requested_tob_skills};
pub(crate) use run_plugin_finding_adapter::run_plugin_finding_adapter;
pub(crate) use shinsa_assessment::run_shinsa_assessment;

mod list_shinsa_frameworks;
mod list_tob_skills;
mod run_plugin_finding_adapter;
mod shinsa_assessment;
