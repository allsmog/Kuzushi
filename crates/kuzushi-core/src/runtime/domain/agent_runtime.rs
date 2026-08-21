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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLoopOutcome {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<Value>,
    pub steps_used: u32,
    pub truncated: bool,
    /// Sum of per-step costs surfaced by the bridge.
    #[serde(default)]
    pub cost_usd: f64,
    #[serde(
        default = "default_agent_loop_cost_exact",
        skip_serializing_if = "is_true"
    )]
    pub cost_usd_exact: bool,
    pub transcript: Vec<LoopHistoryEntry>,
}

impl Default for AgentLoopOutcome {
    fn default() -> Self {
        Self {
            text: String::new(),
            structured: None,
            steps_used: 0,
            truncated: false,
            cost_usd: 0.0,
            cost_usd_exact: true,
            transcript: Vec::new(),
        }
    }
}

const fn default_agent_loop_cost_exact() -> bool {
    true
}

const fn is_true(value: &bool) -> bool {
    *value
}

#[cfg(test)]
mod agent_loop_outcome_serde_tests {
    use super::*;

    #[test]
    fn legacy_cost_deserializes_as_exact_and_true_is_omitted() {
        let legacy: AgentLoopOutcome = serde_json::from_value(serde_json::json!({
            "text": "done",
            "steps_used": 1,
            "truncated": false,
            "cost_usd": 0.25,
            "transcript": [],
        }))
        .unwrap();

        assert!(legacy.cost_usd_exact);
        assert!(serde_json::to_value(legacy)
            .unwrap()
            .get("cost_usd_exact")
            .is_none());
    }

    #[test]
    fn unresolved_cost_serializes_explicit_false() {
        let outcome = AgentLoopOutcome {
            cost_usd_exact: false,
            ..AgentLoopOutcome::default()
        };

        assert_eq!(
            serde_json::to_value(outcome).unwrap()["cost_usd_exact"],
            serde_json::json!(false)
        );
    }
}

#[async_trait]
pub trait AgentRuntime: Send + Sync {
    /// Verify that `model` can authenticate before any tool executor performs
    /// local setup or starts a provider bridge. Runtimes that do not own
    /// credential resolution retain the compatibility no-op.
    fn preflight_model_blocking(&self, _model: &str) -> Result<()> {
        Ok(())
    }

    fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        anyhow::bail!("agent runtime does not support generic LangGraph queries")
    }

    /// Query plus provider-reported token telemetry. Existing runtimes keep
    /// working through the unavailable-usage compatibility receipt; provider
    /// adapters should override this when they can distinguish reported zero
    /// tokens from missing usage metadata.
    fn query_observed_blocking(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        self.query_blocking(request)
            .and_then(AgentQueryResponse::validate_cost)
            .map(observe_legacy_query_response)
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
        let response = self.query_blocking(request)?.validate_cost()?;
        control.ensure_active()?;
        Ok(response)
    }

    fn query_observed_blocking_controlled(
        &self,
        request: AgentQueryRequest,
        control: AgentQueryControl,
    ) -> Result<Observed<AgentQueryResponse>> {
        control.ensure_active()?;
        let response = self.query_observed_blocking(request)?;
        control.ensure_active()?;
        Ok(response)
    }

    async fn query(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        isolate_blocking(move || {
            self.query_blocking(request)
                .and_then(AgentQueryResponse::validate_cost)
        })
    }

    async fn query_observed(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        isolate_blocking(move || self.query_observed_blocking(request))
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome>;

    fn triage_finding_observed_blocking(
        &self,
        request: TriageRequest,
    ) -> Result<Observed<TriageOutcome>> {
        self.triage_finding_blocking(request)
            .and_then(TriageOutcome::validate_cost)
            .map(Observed::without_usage)
    }

    async fn triage_finding(&self, request: TriageRequest) -> Result<TriageOutcome> {
        isolate_blocking(move || {
            self.triage_finding_blocking(request)
                .and_then(TriageOutcome::validate_cost)
        })
    }

    async fn triage_finding_observed(
        &self,
        request: TriageRequest,
    ) -> Result<Observed<TriageOutcome>> {
        isolate_blocking(move || self.triage_finding_observed_blocking(request))
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

    fn next_step_observed_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<Observed<AgentLoopStep>> {
        self.next_step_blocking(request, history)
            .and_then(AgentLoopStep::validate_cost)
            .map(Observed::without_usage)
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
        request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        self.query_blocking(with_subagent_role_prompt(role, request))
            .and_then(AgentQueryResponse::validate_cost)
    }

    fn spawn_subagent_observed_blocking(
        &self,
        role: SubagentRole,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        self.query_observed_blocking(with_subagent_role_prompt(role, request))
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost))
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
            .and_then(AgentQueryResponse::validate_cost)
    }
}

fn with_subagent_role_prompt(
    role: SubagentRole,
    mut request: AgentQueryRequest,
) -> AgentQueryRequest {
    let preamble = role.system_prompt_prefix();
    if preamble.is_empty() {
        return request;
    }
    request.system_prompt = if request.system_prompt.is_empty() {
        preamble.to_string()
    } else {
        format!("{preamble}\n{}", request.system_prompt)
    };
    request
}

fn observe_legacy_query_response(response: AgentQueryResponse) -> Observed<AgentQueryResponse> {
    let usage = legacy_query_response_usage(&response);
    Observed::new(response, usage)
}

fn legacy_query_response_usage(response: &AgentQueryResponse) -> ModelTokenUsage {
    if response.input_tokens > 0 || response.output_tokens > 0 {
        ModelTokenUsage::reported(response.input_tokens.into(), response.output_tokens.into())
    } else {
        ModelTokenUsage::unavailable_call()
    }
}

#[cfg(test)]
mod legacy_query_usage_tests {
    use super::*;

    struct LegacyCounterRuntime {
        input_tokens: u32,
        output_tokens: u32,
    }

    impl AgentRuntime for LegacyCounterRuntime {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            Ok(AgentQueryResponse {
                input_tokens: self.input_tokens,
                output_tokens: self.output_tokens,
                ..AgentQueryResponse::default()
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("not used by legacy query telemetry tests")
        }
    }

    #[test]
    fn positive_legacy_counters_are_reported_by_query_and_subagent_defaults() {
        let runtime = LegacyCounterRuntime {
            input_tokens: 17,
            output_tokens: 4,
        };

        let query = runtime.query_observed_blocking(request()).unwrap();
        let subagent = runtime
            .spawn_subagent_observed_blocking(SubagentRole::Generic, request())
            .unwrap();

        assert_eq!(query.usage.observed_counts(), (Some(17), Some(4)));
        assert!(query.usage.is_complete());
        assert_eq!(subagent.usage, query.usage);
    }

    #[test]
    fn legacy_zero_counters_remain_unavailable() {
        let runtime = LegacyCounterRuntime {
            input_tokens: 0,
            output_tokens: 0,
        };

        let observed = runtime.query_observed_blocking(request()).unwrap();

        assert_eq!(observed.usage.observed_counts(), (None, None));
        assert_eq!(observed.usage.fully_reported_calls(), 0);
        assert_eq!(observed.usage.total_calls, 1);
        assert!(!observed.usage.is_complete());
    }

    fn request() -> AgentQueryRequest {
        AgentQueryRequest::new("provider:model", "/tmp", "system", "prompt")
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
