use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentStructuredOutput};
use anyhow::{Context, Result};
use serde_json::Value;
#[cfg(test)]
mod bounded_tests;
mod cached_query;
mod diagnostics;
mod finding_output;
mod parse_json_value_from_agent_text;
mod response_material;
mod structured_json_contract;
#[cfg(test)]
mod tests;

pub(crate) use cached_query::{query_cached_structured_json_with_cost, CachedStructuredJson};
use diagnostics::{build_repair_prompt, repair_failure_error, truncation_error};
#[cfg(test)]
use diagnostics::{MAX_REPAIR_PROMPT_BYTES, MAX_STRUCTURED_DIAGNOSTIC_BYTES};
pub(crate) use finding_output::FindingsOutput;
#[cfg(test)]
pub(crate) use parse_json_value_from_agent_text::parse_json_value_from_agent_text;
#[cfg(test)]
pub(crate) use parse_json_value_from_agent_text::{
    balanced_json_scan_stats, fenced_json_scan_stats, MAX_BALANCED_CANDIDATES,
    MAX_BALANCED_CANDIDATE_BYTES,
};
pub(crate) use parse_json_value_from_agent_text::{
    balanced_json_slices, parse_json_value_from_agent_text_with_strategy,
    try_parse_typed_from_agent_text,
};
pub(crate) use response_material::{
    ensure_response_material_budget, MAX_STRUCTURED_RESPONSE_BYTES,
};
use response_material::{
    ensure_text_parse_budget, formatted_evidence, serialized_value_evidence, ByteEvidence,
    ResponseMaterial,
};
#[cfg(test)]
pub(crate) use structured_json_contract::parse_or_repair_required_structured_json;
#[cfg(test)]
pub(crate) use structured_json_contract::query_required_structured_json;
pub(crate) use structured_json_contract::{
    parse_or_repair_required_structured_json_with_cost, query_required_structured_json_with_cost,
    repair_request_from, CostedStructuredJson, StructuredJsonContract, StructuredOutputError,
};
