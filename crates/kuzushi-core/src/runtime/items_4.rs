use super::prelude::*;
use super::*;

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
