use super::*;

/// Empirical exploit-gated verify: scaffolds a sandboxed test harness from
/// the finding's location and observes whether it crashes. Promotes to
/// `proof_level=4` only on observed crash inside an isolating sandbox.
/// Complementary to (not a replacement for) the LLM-driven `verify:finding`.
use self::input::resolve_prompt_override;
use self::json_fields::{
    normalize_attack_path, normalize_code_citations, normalize_controls, normalize_object_array,
    read_object_bool, read_object_f64, read_object_nullable_string, read_object_string,
    read_object_string_array, read_object_u64, string_or_null,
};
use crate::findings::{Finding, TriageOutcome};
use crate::runtime::AgentQueryRequest;
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use anyhow::{Context, Result};
pub(in crate::modules) use from_tool_input::*;
pub(in crate::modules) use insert_verification_row_id::*;
pub(in crate::modules) use run_verify_finding::*;
use serde_json::{json, Map, Value};
use std::path::Path;
pub(in crate::modules) use verify_exploit_input::*;
mod from_tool_input;
mod insert_verification_row_id;
mod run_verify_finding;
#[cfg(test)]
mod tests;
mod verify_exploit_input;
