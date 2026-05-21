use super::*;

#[async_trait]
impl AgentRuntime for RoutedRuntime<'_> {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        validate_routed_request_model("query", &request.model)?;
        self.inner.query_blocking(request)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        validate_routed_request_model("triage", &request.model)?;
        self.inner.triage_finding_blocking(request)
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
        self.inner.next_step_blocking(request, history)
    }
}

fn validate_routed_request_model(kind: &str, model: &str) -> Result<()> {
    validate_model_spec(model)
        .with_context(|| format!("routed runtime received an invalid {kind} model"))
}
