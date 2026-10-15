use super::*;
use crate::runtime::AgentQueryControl;

#[async_trait]
impl AgentRuntime for RoutedRuntime<'_> {
    fn allowance_binding(&self) -> Option<&crate::allowance::AllowanceBinding> {
        self.inner.allowance_binding()
    }

    fn authorize_tool_policy_blocking(
        &self,
        authorization: &crate::runtime::AgentToolPolicyAuthorization,
    ) -> Result<crate::runtime::AgentToolPolicyReceipt> {
        self.inner.authorize_tool_policy_blocking(authorization)
    }

    fn semantic_cache_identity(
        &self,
        request: &AgentQueryRequest,
    ) -> Option<crate::identity::Blake3Hash> {
        validate_routed_request_model("cache", &request.model).ok()?;
        self.inner.semantic_cache_identity(request)
    }

    fn preflight_model_blocking(&self, model: &str) -> Result<()> {
        validate_routed_request_model("preflight", model)?;
        self.inner.preflight_model_blocking(model)
    }

    fn triage_semantic_cache_identity(
        &self,
        request: &TriageRequest,
    ) -> Option<crate::identity::Blake3Hash> {
        validate_routed_request_model("triage-cache", &request.model).ok()?;
        self.inner.triage_semantic_cache_identity(request)
    }

    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        validate_routed_request_model("query", &request.model)?;
        self.inner
            .query_blocking(request)
            .and_then(AgentQueryResponse::validate_cost)
    }

    fn query_observed_blocking(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        validate_routed_request_model("query", &request.model)?;
        self.inner
            .query_observed_blocking(request)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost))
    }

    fn query_blocking_controlled(
        &self,
        request: AgentQueryRequest,
        control: AgentQueryControl,
    ) -> Result<AgentQueryResponse> {
        validate_routed_request_model("query", &request.model)?;
        self.inner
            .query_blocking_controlled(request, control)
            .and_then(AgentQueryResponse::validate_cost)
    }

    fn query_observed_blocking_controlled(
        &self,
        request: AgentQueryRequest,
        control: AgentQueryControl,
    ) -> Result<Observed<AgentQueryResponse>> {
        validate_routed_request_model("query", &request.model)?;
        self.inner
            .query_observed_blocking_controlled(request, control)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost))
    }

    async fn query_observed(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        validate_routed_request_model("query", &request.model)?;
        self.inner
            .query_observed(request)
            .await
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost))
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        validate_routed_request_model("triage", &request.model)?;
        self.inner
            .triage_finding_blocking(request)
            .and_then(TriageOutcome::validate_cost)
    }

    fn triage_finding_observed_blocking(
        &self,
        request: TriageRequest,
    ) -> Result<Observed<TriageOutcome>> {
        validate_routed_request_model("triage", &request.model)?;
        self.inner
            .triage_finding_observed_blocking(request)
            .and_then(|observed| observed.try_map(TriageOutcome::validate_cost))
    }

    async fn triage_finding_observed(
        &self,
        request: TriageRequest,
    ) -> Result<Observed<TriageOutcome>> {
        validate_routed_request_model("triage", &request.model)?;
        self.inner
            .triage_finding_observed(request)
            .await
            .and_then(|observed| observed.try_map(TriageOutcome::validate_cost))
    }

    fn supports_tools(&self) -> bool {
        self.inner.supports_tools()
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        validate_routed_request_model("tool-loop", &request.model)?;
        self.inner
            .next_step_blocking(request, history)
            .and_then(AgentLoopStep::validate_cost)
    }

    fn next_step_observed_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<Observed<AgentLoopStep>> {
        validate_routed_request_model("tool-loop", &request.model)?;
        self.inner
            .next_step_observed_blocking(request, history)
            .and_then(|observed| observed.try_map(AgentLoopStep::validate_cost))
    }

    fn spawn_subagent_observed_blocking(
        &self,
        role: crate::runtime::SubagentRole,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        validate_routed_request_model("subagent", &request.model)?;
        self.inner
            .spawn_subagent_observed_blocking(role, request)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost))
    }
}

fn validate_routed_request_model(kind: &str, model: &str) -> Result<()> {
    validate_model_spec(model)
        .with_context(|| format!("routed runtime received an invalid {kind} model"))
}
