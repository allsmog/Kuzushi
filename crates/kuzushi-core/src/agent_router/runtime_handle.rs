use super::*;

pub enum RuntimeHandle<'a> {
    Borrowed(&'a dyn AgentRuntime),
    Owned(Arc<dyn AgentRuntime>),
}

impl<'a> RuntimeHandle<'a> {
    fn inner(&self) -> &dyn AgentRuntime {
        match self {
            Self::Borrowed(runtime) => *runtime,
            Self::Owned(runtime) => runtime.as_ref(),
        }
    }
}

#[async_trait]
impl<'a> AgentRuntime for RuntimeHandle<'a> {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.inner().query_blocking(request)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.inner().triage_finding_blocking(request)
    }

    fn supports_tools(&self) -> bool {
        self.inner().supports_tools()
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        self.inner().next_step_blocking(request, history)
    }

    fn preflight_tool_loop_blocking(&self, request: &AgentToolLoopRequest) -> Result<()> {
        self.inner().preflight_tool_loop_blocking(request)
    }

    fn model_for_tier(&self, tier: crate::runtime::ModelTier, configured: &str) -> String {
        self.inner().model_for_tier(tier, configured)
    }

    fn spawn_subagent_blocking(
        &self,
        role: crate::runtime::SubagentRole,
        request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        self.inner().spawn_subagent_blocking(role, request)
    }
}
