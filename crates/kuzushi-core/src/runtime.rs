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
        }
    }

    pub fn with_tool_policy(mut self, tool_policy: AgentToolPolicy) -> Self {
        self.tool_policy = tool_policy;
        self
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub input: Value,
    pub call_id: String,
}

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
    pub max_steps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum AgentLoopStep {
    ToolCall {
        #[serde(flatten)]
        call: ToolCall,
    },
    Final {
        #[serde(default)]
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        structured: Option<Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
    },
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoopHistoryEntry {
    AssistantToolCall(ToolCall),
    ToolResult(ToolResult),
    AssistantText(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentLoopOutcome {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
    pub steps_used: u32,
    pub truncated: bool,
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

    /// Resolve a tier handle (`Cheap`/`Mid`/`Deep`) to a concrete model
    /// name. Default: pass-through to whatever the operator
    /// configured. Providers that can route across model classes
    /// override this so multi-stage triage can ask for a cheap pass.
    fn model_for_tier(&self, _tier: ModelTier, configured: &str) -> String {
        configured.to_string()
    }

    /// Resolve a role key (`triage`, `deep_auditor`, `classifier_gate`,
    /// `full_mode_multi`, etc.) to a concrete model name. Default
    /// pass-through: the configured operator model wins. The
    /// `RoutedRuntime` wrapper overrides this so callers honour
    /// `~/.kuzushi/models.toml [roles.<key>]` without requiring every
    /// tool dispatch site to thread an `Arc<dyn AgentRuntime>`. Pass
    /// the role key as a `&str` rather than the typed `AgentRole`
    /// enum so this trait stays free of the `agent_router` dep cycle;
    /// providers parse the key locally if they care.
    fn model_for_role(&self, _role_key: &str, configured: &str) -> String {
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

    fn supports_tools(&self) -> bool {
        false
    }

    fn next_step_blocking(
        &self,
        _request: &AgentToolLoopRequest,
        _history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        anyhow::bail!(
            "agent runtime does not support tool-augmented loops; implement next_step_blocking"
        )
    }
}

pub fn run_tool_loop(
    runtime: &dyn AgentRuntime,
    request: &AgentToolLoopRequest,
    handler: &mut dyn ToolCallHandler,
) -> Result<AgentLoopOutcome> {
    if !runtime.supports_tools() {
        anyhow::bail!("runtime does not support tool-augmented loops");
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
        AgentQueryRequest {
            model: "openai:gpt-4.1".to_string(),
            cwd: PathBuf::from("."),
            system_prompt: system_prompt.to_string(),
            prompt: "hello".to_string(),
            tool_policy: AgentToolPolicy::default(),
        }
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
