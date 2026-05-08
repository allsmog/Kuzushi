use super::prelude::*;
use super::*;

#[async_trait]
impl AgentRuntime for RoutedRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.inner.query_blocking(request)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
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
        self.inner.next_step_blocking(request, history)
    }
}
