use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentStructuredOutput};
use anyhow::{Context, Result};
use serde_json::Value;
mod parse_json_value_from_agent_text;
mod structured_json_contract;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use parse_json_value_from_agent_text::parse_json_value_from_agent_text;
pub(crate) use parse_json_value_from_agent_text::{
    balanced_json_slices, parse_json_value_from_agent_text_with_strategy,
    try_parse_typed_from_agent_text,
};
use parse_json_value_from_agent_text::{build_repair_prompt, raw_agent_response};
#[cfg(test)]
pub(crate) use structured_json_contract::parse_or_repair_required_structured_json;
pub(crate) use structured_json_contract::{
    parse_or_repair_required_structured_json_with_cost, query_required_structured_json,
    query_required_structured_json_with_cost, repair_request_from, CostedStructuredJson,
    StructuredJsonContract,
};
