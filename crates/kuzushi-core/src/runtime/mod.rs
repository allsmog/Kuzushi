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
mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod items_1;
mod items_2;
mod items_3;
mod items_4;
mod run_tool_loop;
#[cfg(test)]
mod tests;

pub use items_1::append_structured_output_contract;
pub use items_1::AgentQueryRequest;
pub use items_1::AgentStructuredOutput;
pub use items_1::AgentToolPolicy;
pub use items_1::TriageRequest;
pub use items_2::AgentQueryResponse;
pub use items_2::ModelTier;
pub use items_2::SubagentRole;
pub use items_3::AgentLoopStep;
pub use items_3::AgentTool;
pub use items_3::AgentToolLoopRequest;
pub use items_3::ToolBox;
pub use items_3::ToolCall;
pub use items_3::ToolCallHandler;
pub use items_3::ToolResult;
pub use items_4::AgentLoopOutcome;
pub use items_4::AgentRuntime;
pub use items_4::LoopHistoryEntry;
pub use run_tool_loop::run_tool_loop;
