use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::findings::{Finding, TriageOutcome};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub finding: Finding,
    pub prompt_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQueryRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub system_prompt: String,
    pub prompt: String,
    #[serde(default)]
    pub tool_policy: AgentToolPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_output: Option<AgentStructuredOutput>,
    /// Per-request reasoning effort override ("low" | "medium" | "high" | "xhigh").
    /// `None` falls back to the runtime-level setting (env or runtime default).
    /// Tools that need substantial code analysis (e.g. carlini-threat-hunt)
    /// should set this; the bridge defaults to "low" for cheap calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking_level: Option<String>,
}

impl AgentQueryRequest {
    pub fn new(
        model: impl Into<String>,
        cwd: impl Into<PathBuf>,
        system_prompt: impl Into<String>,
        prompt: impl Into<String>,
    ) -> Self {
        Self {
            model: model.into(),
            cwd: cwd.into(),
            system_prompt: system_prompt.into(),
            prompt: prompt.into(),
            tool_policy: AgentToolPolicy::default(),
            structured_output: None,
            thinking_level: None,
        }
    }

    pub fn with_tool_policy(mut self, tool_policy: AgentToolPolicy) -> Self {
        self.tool_policy = tool_policy;
        self
    }

    pub fn with_structured_output(mut self, structured_output: AgentStructuredOutput) -> Self {
        self.structured_output = Some(structured_output);
        self
    }

    pub fn with_thinking_level(mut self, thinking_level: impl Into<String>) -> Self {
        self.thinking_level = Some(thinking_level.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgentStructuredOutput {
    pub name: String,
    pub schema: Value,
    #[serde(default)]
    pub strict: bool,
}

impl AgentStructuredOutput {
    pub fn json_schema(name: impl Into<String>, schema: Value) -> Self {
        Self {
            name: name.into(),
            schema,
            strict: true,
        }
    }
}

pub fn append_structured_output_contract(
    system_prompt: &str,
    structured_output: Option<&AgentStructuredOutput>,
) -> String {
    let Some(contract) = structured_output else {
        return system_prompt.to_string();
    };
    let schema = serde_json::to_string_pretty(&contract.schema)
        .unwrap_or_else(|_| contract.schema.to_string());
    let strict = if contract.strict { "strict " } else { "" };
    format!(
        "{system_prompt}\n\nStructured output contract:\n\
         Return only {strict}JSON for `{name}`. Do not include markdown fences, prose, or trailing commentary.\n\
         Required JSON schema:\n{schema}",
        name = contract.name,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentToolPolicy {
    pub profile: String,
    #[serde(default)]
    pub tools: Vec<String>,
}

impl AgentToolPolicy {
    pub fn new(
        profile: impl Into<String>,
        tools: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            profile: profile.into(),
            tools: tools.into_iter().map(Into::into).collect(),
        }
    }

    pub fn is_default(&self) -> bool {
        self.profile == "default" && self.tools.is_empty()
    }
}

impl Default for AgentToolPolicy {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            tools: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentQueryResponse {
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub structured: Option<Value>,
    /// Cost in USD for this single API call. Populated by providers
    /// that track token usage (e.g. `AnthropicOAuthRuntime` reads
    /// `usage.input_tokens` / `usage.output_tokens` and multiplies by
    /// the per-model rate). Defaults to `0.0` for providers that
    /// don't surface usage.
    #[serde(default)]
    pub cost_usd: f64,
    /// Input/output token counts when the provider reports them.
    /// Used for cost aggregation and as a sanity check on the cost
    /// calculation. Both default to `0`.
    #[serde(default)]
    pub input_tokens: u32,
    #[serde(default)]
    pub output_tokens: u32,
}

/// Model-capability tier used by routing in multi-stage triage. The
/// concrete model name (`claude-haiku-4-5-...`, `claude-sonnet-4-6`,
/// `claude-opus-4-7`) is provider-specific; this enum is the
/// provider-agnostic handle Stage 2 / Stage 3 dispatch keys off of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelTier {
    /// Cheapest tier — Haiku-class. ~$0.001/k tokens. Use for fast
    /// scans + Stage 2 noise reduction.
    Cheap,
    /// Mid-tier — current Sonnet. Default when no explicit tier is
    /// requested.
    Mid,
    /// Most-capable tier — Opus. Reserve for Stage 3 verify on the
    /// few survivors that warrant the cost.
    Deep,
}

/// Specialist role for a sub-agent. Mirrors the RoboDuck pattern of
/// spawning narrowly-scoped sub-agents per task so the main agent's
/// context stays focused. Each role prepends a deterministic
/// system-prompt preamble so providers don't need any role-specific code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubagentRole {
    /// Generic sub-agent — same behaviour as `query`, used as a sentinel.
    Generic,
    /// Reasons about a single `unsafe { ... }` block in Rust: bounds,
    /// alignment, raw-pointer arithmetic, `from_raw_parts*`, `transmute`.
    UnsafeBlockReasoner,
    /// Reasons about lifetimes and aliasing: `'static` smuggling,
    /// mutable aliasing, `&mut` from raw pointer, `Pin` violations.
    LifetimeAliasingReasoner,
    /// Reasons about FFI boundaries: `extern "C"` ABI mismatches,
    /// ownership transfer, `repr(C)` invariant misuse.
    FfiBoundaryReasoner,
}

impl SubagentRole {
    /// Human-readable role name used in logs and audit trails.
    pub fn name(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::UnsafeBlockReasoner => "unsafe-block",
            Self::LifetimeAliasingReasoner => "lifetime-aliasing",
            Self::FfiBoundaryReasoner => "ffi-boundary",
        }
    }

    /// Deterministic system-prompt prefix prepended to the caller's prompt.
    /// Empty for `Generic` so existing callers see no behavioural change.
    pub fn system_prompt_prefix(self) -> &'static str {
        match self {
            Self::Generic => "",
            Self::UnsafeBlockReasoner => {
                "You are a focused Rust unsafe-block reasoner. Restrict analysis to the \
                 single `unsafe { ... }` region you are given. Cite line numbers. Look \
                 for: raw-pointer arithmetic, `from_raw_parts*` on attacker-influenced \
                 lengths, `transmute`, alignment violations, uninitialised reads. \
                 Refuse claims that cannot be grounded in the supplied source.\n"
            }
            Self::LifetimeAliasingReasoner => {
                "You are a focused Rust lifetime and aliasing reasoner. Restrict \
                 analysis to lifetime annotations, mutable aliasing, `Pin`/`!Unpin` \
                 invariants, `'static` smuggling, and `&mut` derived from raw pointers. \
                 Cite line numbers. Be conservative when the borrow checker has not \
                 been overridden.\n"
            }
            Self::FfiBoundaryReasoner => {
                "You are a focused Rust FFI-boundary reasoner. Restrict analysis to \
                 `extern \"C\"` declarations, ABI mismatches, ownership transfer across \
                 the boundary, `repr(C)` invariant violations, and null/dangling \
                 pointers reaching foreign code. Cite line numbers.\n"
            }
        }
    }
}

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTool {
    /// Tool identifier exposed to the model (e.g. `read_source`).
    pub name: String,
    pub description: String,
    /// JSON Schema for the tool's input. Forwarded verbatim to Anthropic /
    /// OpenAI's tool-use API.
    pub input_schema: Value,
}

/// One pending tool call from the model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub input: Value,
    /// Provider-supplied id used to thread the result back into the next
    /// turn (Anthropic `tool_use.id`, OpenAI `tool_call.id`).
    pub call_id: String,
}

/// Result of executing a tool call locally. Forwarded back to the model on
/// the next step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub call_id: String,
    pub output: Value,
    #[serde(default)]
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToolLoopRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub system_prompt: String,
    pub prompt: String,
    #[serde(default)]
    pub tools: Vec<AgentTool>,
    /// Hard upper bound on the number of model round-trips. The driver
    /// stops here and surfaces the partial transcript even if the model
    /// hasn't returned a final.
    pub max_steps: u32,
}

/// Bridge response for one step.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum AgentLoopStep {
    /// Model invoked a tool — host should execute and call `next_step`
    /// again with the result attached.
    ToolCall {
        #[serde(flatten)]
        call: ToolCall,
    },
    /// Model returned a final answer — driver should exit the loop.
    Final {
        #[serde(default)]
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        structured: Option<Value>,
        /// Optional cost surfaced by the bridge for spend-ledger settlement.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
    },
}

/// Trait implemented by hosts that can dispatch a single round-trip.
/// Stateless from the trait's POV — history is provided by the driver.
pub trait ToolCallHandler: Send {
    fn run(&mut self, call: &ToolCall) -> Result<ToolResult>;
}

impl<F> ToolCallHandler for F
where
    F: FnMut(&ToolCall) -> Result<ToolResult> + Send,
{
    fn run(&mut self, call: &ToolCall) -> Result<ToolResult> {
        (self)(call)
    }
}

/// Map-backed handler — for tests + simple cases. Each tool is a closure.
pub struct ToolBox {
    tools: BTreeMap<String, Box<dyn FnMut(&ToolCall) -> Result<ToolResult> + Send>>,
}

impl Default for ToolBox {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolBox {
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
        }
    }

    pub fn register<F>(&mut self, name: impl Into<String>, handler: F) -> &mut Self
    where
        F: FnMut(&ToolCall) -> Result<ToolResult> + Send + 'static,
    {
        self.tools.insert(name.into(), Box::new(handler));
        self
    }
}

impl ToolCallHandler for ToolBox {
    fn run(&mut self, call: &ToolCall) -> Result<ToolResult> {
        match self.tools.get_mut(&call.name) {
            Some(handler) => handler(call),
            None => Ok(ToolResult {
                call_id: call.call_id.clone(),
                output: serde_json::json!({
                    "error": format!("unknown tool {:?}", call.name)
                }),
                is_error: true,
            }),
        }
    }
}

/// One transcript entry — used by the driver and forwarded to the runtime
/// so each step can reconstruct the conversation history. The shape is
/// intentionally close to the Anthropic message format so the bridge can
/// pass it through without re-shaping.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoopHistoryEntry {
    AssistantToolCall(ToolCall),
    ToolResult(ToolResult),
    AssistantText(String),
}

/// Final outcome of [`run_tool_loop`]. `transcript` is always populated —
/// callers get the full step history even on truncation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentLoopOutcome {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
    pub steps_used: u32,
    pub truncated: bool,
    /// Sum of per-step costs surfaced by the bridge.
    #[serde(default)]
    pub cost_usd: f64,
    pub transcript: Vec<LoopHistoryEntry>,
}

#[async_trait]
pub trait AgentRuntime: Send + Sync {
    fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        anyhow::bail!("agent runtime does not support generic pi-agent-core queries")
    }

    async fn query(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.query_blocking(request)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome>;

    async fn triage_finding(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.triage_finding_blocking(request)
    }

    /// Whether this runtime supports tool-augmented loops.
    fn supports_tools(&self) -> bool {
        false
    }

    /// One round-trip in a tool-augmented loop. The runtime is responsible
    /// for talking to the model with `request.tools` and the running
    /// `history`; it must not execute the tools itself. Default impl is
    /// errored so existing impls don't have to change until they need it.
    fn next_step_blocking(
        &self,
        _request: &AgentToolLoopRequest,
        _history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        anyhow::bail!(
            "agent runtime does not support tool-augmented loops; \
             implement next_step_blocking or call query_blocking instead"
        )
    }

    /// Resolve a tier handle (`Cheap`/`Mid`/`Deep`) to a concrete model
    /// name. Default: pass-through to whatever the operator
    /// configured. Providers that can route across model classes
    /// override this so multi-stage triage can ask for a cheap pass.
    fn model_for_tier(&self, _tier: ModelTier, configured: &str) -> String {
        configured.to_string()
    }

    /// Spawn a role-scoped sub-agent. The default implementation prepends
    /// the role's system-prompt preamble and forwards to `query_blocking`,
    /// so any provider that implements `query_blocking` automatically gains
    /// sub-agent support without further changes. Providers that can run
    /// children in genuinely separate sessions / workers may override this.
    fn spawn_subagent_blocking(
        &self,
        role: SubagentRole,
        mut request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        let preamble = role.system_prompt_prefix();
        if !preamble.is_empty() {
            request.system_prompt = if request.system_prompt.is_empty() {
                preamble.to_string()
            } else {
                format!("{preamble}\n{}", request.system_prompt)
            };
        }
        self.query_blocking(request)
    }

    /// Async wrapper for `spawn_subagent_blocking`. Override when the
    /// provider can dispatch role-scoped queries in parallel without
    /// blocking the executor.
    async fn spawn_subagent(
        &self,
        role: SubagentRole,
        request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        self.spawn_subagent_blocking(role, request)
    }
}

/// Drive a tool-augmented loop to completion (or `max_steps`). The driver
/// is the canonical loop body — runtime impls only handle one step at a
/// time, so they don't need to know about `ToolBox` or history shape.
pub fn run_tool_loop(
    runtime: &dyn AgentRuntime,
    request: &AgentToolLoopRequest,
    handler: &mut dyn ToolCallHandler,
) -> Result<AgentLoopOutcome> {
    if !runtime.supports_tools() {
        anyhow::bail!(
            "runtime does not support tool-augmented loops (set supports_tools() = true \
             and implement next_step_blocking)"
        );
    }

    let mut transcript: Vec<LoopHistoryEntry> = Vec::new();
    let mut cost_usd = 0.0f64;

    let cap = request.max_steps.max(1);
    for step in 0..cap {
        let outcome = runtime
            .next_step_blocking(request, &transcript)
            .with_context(|| format!("agent loop step {step} failed"))?;
        match outcome {
            AgentLoopStep::ToolCall { call } => {
                transcript.push(LoopHistoryEntry::AssistantToolCall(call.clone()));
                let result = handler.run(&call).unwrap_or_else(|err| ToolResult {
                    call_id: call.call_id.clone(),
                    output: serde_json::json!({ "error": err.to_string() }),
                    is_error: true,
                });
                transcript.push(LoopHistoryEntry::ToolResult(result));
            }
            AgentLoopStep::Final {
                text,
                structured,
                cost_usd: step_cost,
            } => {
                if let Some(c) = step_cost {
                    cost_usd += c;
                }
                if !text.is_empty() {
                    transcript.push(LoopHistoryEntry::AssistantText(text.clone()));
                }
                return Ok(AgentLoopOutcome {
                    text,
                    structured,
                    steps_used: step + 1,
                    truncated: false,
                    cost_usd,
                    transcript,
                });
            }
        }
    }

    // Hit max_steps without a Final.
    Ok(AgentLoopOutcome {
        text: String::new(),
        structured: None,
        steps_used: cap,
        truncated: true,
        cost_usd,
        transcript,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock runtime that walks a scripted sequence of [`AgentLoopStep`] outputs
    /// — used to exercise the driver without a real bridge.
    struct ScriptedRuntime {
        steps: Mutex<Vec<AgentLoopStep>>,
        seen: Mutex<Vec<usize>>, // history length seen by each call
    }

    impl ScriptedRuntime {
        fn new(steps: Vec<AgentLoopStep>) -> Self {
            Self {
                steps: Mutex::new(steps),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl AgentRuntime for ScriptedRuntime {
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("not used in these tests")
        }
        fn supports_tools(&self) -> bool {
            true
        }
        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            self.seen.lock().unwrap().push(history.len());
            let mut s = self.steps.lock().unwrap();
            if s.is_empty() {
                anyhow::bail!("scripted runtime exhausted")
            }
            Ok(s.remove(0))
        }
    }

    fn req() -> AgentToolLoopRequest {
        AgentToolLoopRequest {
            model: "anthropic:claude-sonnet-4-6".to_string(),
            cwd: PathBuf::from("/tmp"),
            system_prompt: "you are a tester".to_string(),
            prompt: "do the thing".to_string(),
            tools: vec![AgentTool {
                name: "read_source".to_string(),
                description: "read a file".to_string(),
                input_schema: serde_json::json!({ "type": "object" }),
            }],
            max_steps: 5,
        }
    }

    #[test]
    fn driver_returns_final_in_one_step() {
        let runtime = ScriptedRuntime::new(vec![AgentLoopStep::Final {
            text: "done".to_string(),
            structured: Some(serde_json::json!({"verdict": "tp"})),
            cost_usd: Some(0.01),
        }]);
        let mut tb = ToolBox::new();
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        assert_eq!(outcome.text, "done");
        assert_eq!(outcome.steps_used, 1);
        assert!(!outcome.truncated);
        assert_eq!(outcome.cost_usd, 0.01);
        assert_eq!(outcome.transcript.len(), 1);
        assert!(matches!(
            outcome.transcript[0],
            LoopHistoryEntry::AssistantText(_)
        ));
    }

    #[test]
    fn driver_threads_tool_call_through_handler() {
        let runtime = ScriptedRuntime::new(vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "read_source".to_string(),
                    input: serde_json::json!({ "path": "src/foo.rs" }),
                    call_id: "call_1".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "saw foo".to_string(),
                structured: None,
                cost_usd: None,
            },
        ]);
        let mut tb = ToolBox::new();
        tb.register("read_source", |call| {
            assert_eq!(call.name, "read_source");
            Ok(ToolResult {
                call_id: call.call_id.clone(),
                output: serde_json::json!({ "contents": "fn main() {}" }),
                is_error: false,
            })
        });
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        assert_eq!(outcome.text, "saw foo");
        assert_eq!(outcome.steps_used, 2);
        // Transcript: ToolCall, ToolResult, AssistantText.
        assert_eq!(outcome.transcript.len(), 3);
        assert!(matches!(
            outcome.transcript[0],
            LoopHistoryEntry::AssistantToolCall(_)
        ));
        assert!(matches!(
            outcome.transcript[1],
            LoopHistoryEntry::ToolResult(_)
        ));
        // History grew between calls — second runtime call should have seen
        // the tool call + result.
        let seen = runtime.seen.lock().unwrap();
        assert_eq!(seen[0], 0);
        assert_eq!(seen[1], 2);
    }

    #[test]
    fn driver_marks_truncation_at_max_steps() {
        // Five tool calls in a row, max_steps=3 → truncate after 3rd ToolCall.
        let runtime = ScriptedRuntime::new(
            (0..5)
                .map(|i| AgentLoopStep::ToolCall {
                    call: ToolCall {
                        name: "read_source".to_string(),
                        input: serde_json::Value::Null,
                        call_id: format!("call_{i}"),
                    },
                })
                .collect(),
        );
        let mut tb = ToolBox::new();
        tb.register("read_source", |call| {
            Ok(ToolResult {
                call_id: call.call_id.clone(),
                output: serde_json::Value::Null,
                is_error: false,
            })
        });
        let mut request = req();
        request.max_steps = 3;
        let outcome = run_tool_loop(&runtime, &request, &mut tb).unwrap();
        assert!(outcome.truncated);
        assert_eq!(outcome.steps_used, 3);
    }

    #[test]
    fn unknown_tool_is_returned_as_error_result_not_panic() {
        let runtime = ScriptedRuntime::new(vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "no_such_tool".to_string(),
                    input: serde_json::Value::Null,
                    call_id: "call_x".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "ok".to_string(),
                structured: None,
                cost_usd: None,
            },
        ]);
        let mut tb = ToolBox::new();
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        assert_eq!(outcome.text, "ok");
        // The error result must have been threaded through to the next step.
        let result = outcome
            .transcript
            .iter()
            .find_map(|e| match e {
                LoopHistoryEntry::ToolResult(r) => Some(r),
                _ => None,
            })
            .expect("expected a ToolResult in transcript");
        assert!(result.is_error);
        assert!(
            result.output.to_string().contains("unknown tool"),
            "got {:?}",
            result.output
        );
    }

    #[test]
    fn handler_panic_is_caught_as_error_result() {
        // Defence in depth: a tool that panics shouldn't unwind the loop —
        // catch in the handler closure and return a structured error.
        let runtime = ScriptedRuntime::new(vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "buggy".to_string(),
                    input: serde_json::Value::Null,
                    call_id: "c1".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "ok".to_string(),
                structured: None,
                cost_usd: None,
            },
        ]);
        let mut tb = ToolBox::new();
        tb.register("buggy", |_| anyhow::bail!("simulated tool failure"));
        let outcome = run_tool_loop(&runtime, &req(), &mut tb).unwrap();
        let result = outcome
            .transcript
            .iter()
            .find_map(|e| match e {
                LoopHistoryEntry::ToolResult(r) => Some(r),
                _ => None,
            })
            .expect("expected a ToolResult");
        assert!(result.is_error);
        assert!(result.output.to_string().contains("simulated tool failure"));
    }

    #[test]
    fn legacy_runtime_without_supports_tools_is_rejected() {
        struct LegacyRuntime;
        impl AgentRuntime for LegacyRuntime {
            fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
                unreachable!()
            }
        }
        let mut tb = ToolBox::new();
        let err = run_tool_loop(&LegacyRuntime, &req(), &mut tb)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not support tool-augmented loops"),
            "{err}"
        );
    }
    /// Stub runtime that records the system prompt it received so we can
    /// verify the role preamble is prepended exactly once.
    #[derive(Default)]
    struct RecordingRuntime {
        last_system_prompt: Mutex<Option<String>>,
    }

    impl AgentRuntime for RecordingRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            *self.last_system_prompt.lock().unwrap() = Some(request.system_prompt.clone());
            Ok(AgentQueryResponse {
                text: "ok".to_string(),
                structured: None,
                ..Default::default()
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("not exercised in this test")
        }
    }

    fn request(system_prompt: &str) -> AgentQueryRequest {
        AgentQueryRequest::new("openai:gpt-4.1", PathBuf::from("."), system_prompt, "hello")
    }

    #[test]
    fn generic_role_does_not_modify_system_prompt() {
        let runtime = RecordingRuntime::default();
        runtime
            .spawn_subagent_blocking(SubagentRole::Generic, request("base prompt"))
            .unwrap();
        assert_eq!(
            runtime.last_system_prompt.lock().unwrap().as_deref(),
            Some("base prompt")
        );
    }

    #[test]
    fn unsafe_block_role_prepends_preamble() {
        let runtime = RecordingRuntime::default();
        runtime
            .spawn_subagent_blocking(SubagentRole::UnsafeBlockReasoner, request("base"))
            .unwrap();
        let recorded = runtime.last_system_prompt.lock().unwrap().clone().unwrap();
        assert!(recorded.starts_with("You are a focused Rust unsafe-block reasoner."));
        assert!(recorded.ends_with("base"));
    }

    #[test]
    fn empty_base_prompt_yields_pure_preamble() {
        let runtime = RecordingRuntime::default();
        runtime
            .spawn_subagent_blocking(SubagentRole::FfiBoundaryReasoner, request(""))
            .unwrap();
        let recorded = runtime.last_system_prompt.lock().unwrap().clone().unwrap();
        // No leading newline when base was empty.
        assert!(recorded.starts_with("You are a focused Rust FFI-boundary reasoner."));
        assert!(!recorded.contains("\n\n"));
    }

    #[test]
    fn role_names_are_stable() {
        assert_eq!(SubagentRole::Generic.name(), "generic");
        assert_eq!(SubagentRole::UnsafeBlockReasoner.name(), "unsafe-block");
        assert_eq!(
            SubagentRole::LifetimeAliasingReasoner.name(),
            "lifetime-aliasing"
        );
        assert_eq!(SubagentRole::FfiBoundaryReasoner.name(), "ffi-boundary");
    }
}
