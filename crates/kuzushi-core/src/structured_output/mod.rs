use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentStructuredOutput};
use anyhow::{Context, Result};
pub(crate) use parse_json_value_from_agent_text::*;
use serde_json::Value;
mod parse_json_value_from_agent_text;
mod structured_json_contract;
#[cfg(test)]
mod tests;

pub(crate) use parse_json_value_from_agent_text::balanced_json_slices;
pub(crate) use parse_json_value_from_agent_text::parse_json_value_from_agent_text;
pub(crate) use parse_json_value_from_agent_text::try_parse_typed_from_agent_text;
pub(crate) use structured_json_contract::{
    parse_or_repair_required_structured_json, parse_or_repair_required_structured_json_with_cost,
    query_required_structured_json, query_required_structured_json_with_cost, repair_request_from,
    CostedStructuredJson, StructuredJsonContract,
};
