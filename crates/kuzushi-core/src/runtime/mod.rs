use crate::findings::{Finding, TriageOutcome};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub mod application;
pub mod domain;
pub mod mcp_probe;
pub mod policy;
#[cfg(test)]
mod tests;
mod traced_runtime;

pub use application::run_tool_loop;
pub use domain::{
    append_structured_output_contract, AgentLoopOutcome, AgentLoopStep, AgentQueryRequest,
    AgentQueryResponse, AgentRuntime, AgentRuntimeOptions, AgentStructuredOutput, AgentTool,
    AgentToolLoopRequest, AgentToolPolicy, LoopHistoryEntry, McpAttachment, ModelTier,
    SubagentRole, ToolBox, ToolCall, ToolCallHandler, ToolResult, TriageRequest,
};
pub use mcp_probe::{
    mcp_attachment_plan_for_target, plan_contains, McpArtifactSpec, MCP_ARTIFACT_TABLE,
    MCP_CONSTANT_NAMES,
};
pub use policy::{
    canonical_model_spec, require_configured_model, resolve_explicit_model, validate_model_spec,
};
pub use traced_runtime::{model_provider, prompt_pair_hash, TracedRuntime};

pub fn missing_agent_runtime_message(tool_name: &str) -> String {
    format!(
        "{tool_name} requires an agent runtime; none configured. \
         Set a model with `model anthropic:claude-haiku-4-5` in the shell \
         or `KUZUSHI_MODEL=...` for CLI runs before invoking."
    )
}
