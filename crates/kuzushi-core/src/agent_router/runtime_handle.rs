use super::*;
use crate::runtime::AgentQueryControl;

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
    fn semantic_cache_identity(
        &self,
        request: &AgentQueryRequest,
    ) -> Option<crate::identity::Blake3Hash> {
        self.inner().semantic_cache_identity(request)
    }

    fn preflight_model_blocking(&self, model: &str) -> Result<()> {
        self.inner().preflight_model_blocking(model)
    }

    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.inner()
            .query_blocking(request)
            .and_then(AgentQueryResponse::validate_cost)
    }

    fn query_observed_blocking(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        self.inner()
            .query_observed_blocking(request)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost))
    }

    fn query_blocking_controlled(
        &self,
        request: AgentQueryRequest,
        control: AgentQueryControl,
    ) -> Result<AgentQueryResponse> {
        self.inner()
            .query_blocking_controlled(request, control)
            .and_then(AgentQueryResponse::validate_cost)
    }

    fn query_observed_blocking_controlled(
        &self,
        request: AgentQueryRequest,
        control: AgentQueryControl,
    ) -> Result<Observed<AgentQueryResponse>> {
        self.inner()
            .query_observed_blocking_controlled(request, control)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost))
    }

    async fn query_observed(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        self.inner()
            .query_observed(request)
            .await
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost))
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.inner()
            .triage_finding_blocking(request)
            .and_then(TriageOutcome::validate_cost)
    }

    fn triage_finding_observed_blocking(
        &self,
        request: TriageRequest,
    ) -> Result<Observed<TriageOutcome>> {
        self.inner()
            .triage_finding_observed_blocking(request)
            .and_then(|observed| observed.try_map(TriageOutcome::validate_cost))
    }

    async fn triage_finding_observed(
        &self,
        request: TriageRequest,
    ) -> Result<Observed<TriageOutcome>> {
        self.inner()
            .triage_finding_observed(request)
            .await
            .and_then(|observed| observed.try_map(TriageOutcome::validate_cost))
    }

    fn supports_tools(&self) -> bool {
        self.inner().supports_tools()
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        self.inner()
            .next_step_blocking(request, history)
            .and_then(AgentLoopStep::validate_cost)
    }

    fn next_step_observed_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<Observed<AgentLoopStep>> {
        self.inner()
            .next_step_observed_blocking(request, history)
            .and_then(|observed| observed.try_map(AgentLoopStep::validate_cost))
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
        self.inner()
            .spawn_subagent_blocking(role, request)
            .and_then(AgentQueryResponse::validate_cost)
    }

    fn spawn_subagent_observed_blocking(
        &self,
        role: crate::runtime::SubagentRole,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        self.inner()
            .spawn_subagent_observed_blocking(role, request)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost))
    }
}
