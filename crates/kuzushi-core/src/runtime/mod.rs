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

pub use application::{
    pending_agent_loop_checkpoints, query_blocking_checked, query_blocking_controlled_checked,
    run_tool_loop, run_tool_loop_observed, spawn_subagent_blocking_checked,
    triage_finding_blocking_checked, PendingLoopCheckpoint,
};
pub use domain::runtime_failure_metadata;
pub use domain::{
    append_structured_output_contract, triage_cost_report, AgentLoopOutcome, AgentLoopStep,
    AgentQueryControl, AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentRuntimeOptions,
    AgentStructuredOutput, AgentTool, AgentToolLoopRequest, AgentToolPolicy,
    AgentToolPolicyAuthorization, AgentToolPolicyReceipt, LoopHistoryEntry, McpAttachment,
    ModelTier, ModelTokenUsage, Observed, PromptCacheUsage, RuntimeCost, RuntimeCostReport,
    RuntimeFailure, RuntimeFailureClass, RuntimeFailureMetadata, SubagentRole, ToolBox, ToolCall,
    ToolCallHandler, ToolResult, TriageRequest, DEFAULT_TRIAGE_PROMPT, INTERACTION_REQUIRED_CODE,
    READ_ONLY_ASK_POLICY_ID, READ_ONLY_ASK_POLICY_PROTOCOL_VERSION, READ_ONLY_ASK_TOOLS,
    REQUEST_USER_INPUT_TOOL_NAME,
};
pub use mcp_probe::{
    mcp_attachment_plan_for_target, plan_contains, try_mcp_attachment_plan_for_target,
    McpArtifactSpec, MCP_ARTIFACT_TABLE, MCP_CONSTANT_NAMES,
};
pub use policy::{
    bind_model_auth, bridge_api_key_env_for_model, canonical_model_spec, decide_tie_break,
    is_pre_execution_refusal, public_auth_provider, require_configured_model,
    require_model_auth_binding,
    resolve_explicit_model, validate_model_api_key_env, validate_model_spec, ModelAuthBinding,
    PublicAuthProvider, TieBreakEscalation, TieBreakRefusal,
};
pub use traced_runtime::{
    model_error_class_from_message, model_failure_metadata, model_provider, prompt_pair_hash,
    safe_model_failure_message, TracedRuntime,
};

pub fn missing_agent_runtime_message(tool_name: &str) -> String {
    format!(
        "{tool_name} requires an agent runtime; none configured. \
         Set a model with `model anthropic:claude-haiku-4-5` in the shell \
         or `KUZUSHI_MODEL=...` for CLI runs before invoking."
    )
}
