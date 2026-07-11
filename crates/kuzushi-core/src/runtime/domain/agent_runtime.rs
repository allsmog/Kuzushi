use super::*;

/// Run a synchronous bridge call from an async context without stalling the
/// worker thread. The default async trait methods below only have a blocking
/// implementation to forward to; calling it directly from `async fn` would pin
/// an executor thread for the whole model round-trip and distort scheduling
/// fairness. On a multi-thread Tokio runtime `block_in_place` moves the other
/// tasks off this worker for the duration; on a current-thread runtime (or
/// outside any runtime) there is nothing to yield to, so we invoke inline.
///
/// This keeps blocking work explicit instead of hidden behind an async
/// signature — a runtime that can do genuinely non-blocking dispatch should
/// override the async method rather than rely on this shim.
pub(crate) fn isolate_blocking<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(RuntimeFlavor::MultiThread) => tokio::task::block_in_place(f),
        _ => f(),
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
    /// Sum of per-step costs surfaced by the bridge.
    #[serde(default)]
    pub cost_usd: f64,
    pub transcript: Vec<LoopHistoryEntry>,
}

#[async_trait]
pub trait AgentRuntime: Send + Sync {
    fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        anyhow::bail!("agent runtime does not support generic LangGraph queries")
    }

    /// Execute a query under the caller's invocation cancellation/deadline.
    /// Process-backed runtimes override this to terminate their supervised
    /// transport promptly; the default preserves compatibility while refusing
    /// to report a late result as successful.
    fn query_blocking_controlled(
        &self,
        request: AgentQueryRequest,
        control: AgentQueryControl,
    ) -> Result<AgentQueryResponse> {
        control.ensure_active()?;
        let response = self.query_blocking(request)?;
        control.ensure_active()?;
        Ok(response)
    }

    async fn query(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        isolate_blocking(move || self.query_blocking(request))
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome>;

    async fn triage_finding(&self, request: TriageRequest) -> Result<TriageOutcome> {
        isolate_blocking(move || self.triage_finding_blocking(request))
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

    /// Optional provider-specific readiness check for tool loops. This
    /// should verify auth/scope issues that would otherwise fail on the
    /// first model step after expensive local setup.
    fn preflight_tool_loop_blocking(&self, _request: &AgentToolLoopRequest) -> Result<()> {
        Ok(())
    }

    /// Resolve a tier label (`Cheap`/`Mid`/`Deep`) to the concrete model.
    /// This must preserve the operator-configured model unless an explicit
    /// operator-controlled route chooses a different model before the call.
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
        isolate_blocking(move || self.spawn_subagent_blocking(role, request))
    }
}

#[derive(Clone, Debug, Default)]
pub struct AgentQueryControl {
    cancellation: Option<crate::scan::ScanCancellation>,
    deadline: Option<std::time::Instant>,
}

impl AgentQueryControl {
    pub fn new(
        cancellation: Option<crate::scan::ScanCancellation>,
        deadline: Option<std::time::Instant>,
    ) -> Self {
        Self {
            cancellation,
            deadline,
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(crate::scan::ScanCancellation::is_cancelled)
    }

    pub fn is_expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    }

    pub fn ensure_active(&self) -> Result<()> {
        anyhow::ensure!(!self.is_cancelled(), "agent runtime query was cancelled");
        anyhow::ensure!(!self.is_expired(), "agent runtime query deadline exceeded");
        Ok(())
    }
}
