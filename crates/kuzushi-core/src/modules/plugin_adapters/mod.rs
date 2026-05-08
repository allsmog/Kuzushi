use super::*;

use self::agentic_sast::collect_agentic_repo_inventory;
use self::generic_findings::{
    normalize_agent_json_findings, persist_tool_findings, render_generic_findings_output,
};
use self::input::{positive_usize_input, string_array_or_csv_input, string_input_any};
use self::plugin_resolution::resolve_required_plugin_root;
use self::{
    builtin_module, dag, model_option, resolve_tool_model, resolve_tool_target, target_option,
    tool, tool_with_options,
};
use crate::runtime::AgentQueryRequest;
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use crate::Finding;
use anyhow::{Context, Result};
pub(in crate::modules) use list_shinsa_frameworks::*;
pub(in crate::modules) use list_tob_skills::*;
pub(in crate::modules) use run_plugin_finding_adapter::*;
use serde_json::{json, Value};
pub(in crate::modules) use shinsa_assessment::*;
pub(in crate::modules) use shinsa_module::*;
use std::fs;
use std::path::{Path, PathBuf};
mod list_shinsa_frameworks;
mod list_tob_skills;
mod register_modules;
mod run_plugin_finding_adapter;
mod shinsa_assessment;
mod shinsa_module;
#[cfg(test)]
mod tests;
pub(in crate::modules) use register_modules::{execute_tool, register_modules};
