/// Model-capability tier used by routing in multi-stage triage. The
/// concrete model name (`claude-haiku-4-5-...`, `claude-sonnet-4-6`,
/// `claude-opus-4-7`) is provider-specific; this enum is the
/// provider-agnostic handle Stage 2 / Stage 3 dispatch keys off of.

/// Specialist role for a sub-agent. Mirrors the RoboDuck pattern of
/// spawning narrowly-scoped sub-agents per task so the main agent's
/// context stays focused. Each role prepends a deterministic
/// system-prompt preamble so providers don't need any role-specific code.

// ---------------------------------------------------------------------------
// Tool-augmented agent loop (Phase 4 plumbing).
//
// The deep auditor in Phase 5 will give the model a small set of read-only
// code-navigation tools (read_source, read_definition, find_references,
// list_definitions). Each "step" is one round-trip to the model: the model
// either calls a tool (the host runs it locally and feeds the result back)
// or returns a final answer.
//
// The trait method is default-erroring so existing runtimes that don't
// implement tool use continue to compile — `PiAgentCoreRuntime` overrides
// it in Phase 5 with the bridge envelope. The driver `run_tool_loop`
// lives outside the trait so dispatch logic can evolve without breaking
// downstream impls.
// ---------------------------------------------------------------------------

/// Schema description for one tool the model may call.

/// One pending tool call from the model.

/// Result of executing a tool call locally. Forwarded back to the model on
/// the next step.

/// Bridge response for one step.

/// Trait implemented by hosts that can dispatch a single round-trip.
/// Stateless from the trait's POV — history is provided by the driver.

/// Map-backed handler — for tests + simple cases. Each tool is a closure.

/// One transcript entry — used by the driver and forwarded to the runtime
/// so each step can reconstruct the conversation history. The shape is
/// intentionally close to the Anthropic message format so the bridge can
/// pass it through without re-shaping.

/// Final outcome of [`run_tool_loop`]. `transcript` is always populated —
/// callers get the full step history even on truncation.

/// Drive a tool-augmented loop to completion (or `max_steps`). The driver
/// is the canonical loop body — runtime impls only handle one step at a
/// time, so they don't need to know about `ToolBox` or history shape.
use crate::findings::{Finding, TriageOutcome};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
mod agent_query_contract;
mod query_blocking;
mod response_and_role_types;
mod run;
mod run_tool_loop;
#[cfg(test)]
mod tests;

pub use agent_query_contract::append_structured_output_contract;
pub use agent_query_contract::AgentQueryRequest;
pub use agent_query_contract::AgentStructuredOutput;
pub use agent_query_contract::AgentToolPolicy;
pub use agent_query_contract::TriageRequest;
pub use query_blocking::AgentLoopOutcome;
pub use query_blocking::AgentRuntime;
pub use query_blocking::LoopHistoryEntry;
pub use response_and_role_types::AgentQueryResponse;
pub use response_and_role_types::ModelTier;
pub use response_and_role_types::SubagentRole;
pub use run::AgentLoopStep;
pub use run::AgentTool;
pub use run::AgentToolLoopRequest;
pub use run::ToolBox;
pub use run::ToolCall;
pub use run::ToolCallHandler;
pub use run::ToolResult;
pub use run_tool_loop::run_tool_loop;
