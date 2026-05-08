use super::*;

use self::agentic_sast::{agentic_severity, is_agentic_context_file};
use self::generic_findings::normalize_reported_file_path;
use self::input::{
    optional_nonempty_string, optional_taint_next_string, positive_f64_input, positive_usize_input,
    string_list_input,
};
use self::json_fields::{
    parse_json_object_from_agent_text, read_object_string, read_object_string_array,
    read_object_u64, read_object_value,
};
use self::support::{resolve_tool_target, should_skip_path};
use self::taint_iris::{sanitize_rule_segment, summarize_taint_path};
use crate::findings::{Finding, Severity, StaticProofState};
use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentToolPolicy};
use crate::whitebox_static::{
    agent_tool_policy_for_input, mark_whitebox_static_findings, whitebox_static_profile_requested,
};
use anyhow::{Context, Result};
pub(in crate::modules) use build_taint_iris_next_plan::*;
pub(in crate::modules) use build_taint_iris_next_structural_queries::*;
pub(in crate::modules) use choose_taint_iris_next_backend::*;
pub(in crate::modules) use collect_taint_iris_next_source_files::*;
pub(in crate::modules) use extract_taint_iris_next_evidence::*;
pub(in crate::modules) use from_input::*;
pub(in crate::modules) use from_tool_input::*;
pub(in crate::modules) use rank_taint_iris_next_catalog::*;
pub(in crate::modules) use codeql_dataflow::*;
pub(in crate::modules) use dynamic_catalog::*;
pub(in crate::modules) use joern_dataflow::*;
pub(in crate::modules) use require_taint_iris_next_model::*;
pub(in crate::modules) use run_taint_iris_next_report::*;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
pub(in crate::modules) use syntactic_narrowing::*;
pub(in crate::modules) use taint_iris_next_agent_result::*;
pub(in crate::modules) use taint_iris_next_catalog::*;
pub(in crate::modules) use taint_iris_next_context_languages::*;
pub(in crate::modules) use taint_iris_next_line_matches::*;
pub(in crate::modules) use taint_iris_next_ranked_catalog_entry::*;
pub(in crate::modules) use to_tool_json::*;
use uuid::Uuid;
mod build_taint_iris_next_plan;
mod build_taint_iris_next_structural_queries;
mod choose_taint_iris_next_backend;
mod codeql_dataflow;
mod collect_taint_iris_next_source_files;
mod dynamic_catalog;
mod extract_taint_iris_next_evidence;
mod from_input;
mod from_tool_input;
mod identifier_tokens;
mod joern_dataflow;
mod rank_taint_iris_next_catalog;
mod require_taint_iris_next_model;
mod run_taint_iris_next_report;
mod syntactic_narrowing;
mod taint_iris_next_agent_result;
mod taint_iris_next_catalog;
mod taint_iris_next_context_languages;
mod taint_iris_next_line_matches;
mod taint_iris_next_ranked_catalog_entry;
mod to_tool_json;
pub(in crate::modules::taint_iris_next) use identifier_tokens::*;
#[cfg(test)]
mod tests;
