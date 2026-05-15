use crate::findings::{Finding, TriageOutcome};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub mod application;
pub mod domain;
pub mod policy;
#[cfg(test)]
mod tests;
mod traced_runtime;

pub use application::run_tool_loop;
pub use domain::{
    append_structured_output_contract, AgentLoopOutcome, AgentLoopStep, AgentQueryRequest,
    AgentQueryResponse, AgentRuntime, AgentRuntimeOptions, AgentStructuredOutput, AgentTool,
    AgentToolLoopRequest, AgentToolPolicy, LoopHistoryEntry, ModelTier, SubagentRole, ToolBox,
    ToolCall, ToolCallHandler, ToolResult, TriageRequest,
};
pub use policy::{require_configured_model, resolve_explicit_model, validate_model_spec};
pub use traced_runtime::{model_provider, prompt_pair_hash, TracedRuntime};
