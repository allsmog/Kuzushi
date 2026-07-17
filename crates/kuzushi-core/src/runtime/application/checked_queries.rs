use crate::findings::TriageOutcome;
use crate::runtime::TriageRequest;
use crate::runtime::{
    AgentQueryControl, AgentQueryRequest, AgentQueryResponse, AgentRuntime, SubagentRole,
};
use anyhow::Result;

/// Call a runtime and reject invalid provider cost before returning the
/// response to any aggregation, tracing, or persistence layer.
pub fn query_blocking_checked(
    runtime: &dyn AgentRuntime,
    request: AgentQueryRequest,
) -> Result<AgentQueryResponse> {
    runtime
        .query_blocking(request)
        .and_then(AgentQueryResponse::validate_cost)
}

pub fn query_blocking_controlled_checked(
    runtime: &dyn AgentRuntime,
    request: AgentQueryRequest,
    control: AgentQueryControl,
) -> Result<AgentQueryResponse> {
    runtime
        .query_blocking_controlled(request, control)
        .and_then(AgentQueryResponse::validate_cost)
}

pub fn spawn_subagent_blocking_checked(
    runtime: &dyn AgentRuntime,
    role: SubagentRole,
    request: AgentQueryRequest,
) -> Result<AgentQueryResponse> {
    runtime
        .spawn_subagent_blocking(role, request)
        .and_then(AgentQueryResponse::validate_cost)
}

pub fn triage_finding_blocking_checked(
    runtime: &dyn AgentRuntime,
    request: TriageRequest,
) -> Result<TriageOutcome> {
    runtime
        .triage_finding_blocking(request)
        .and_then(TriageOutcome::validate_cost)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct InvalidCostRuntime(f64);

    impl AgentRuntime for InvalidCostRuntime {
        fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            Ok(AgentQueryResponse {
                cost_usd: self.0,
                ..Default::default()
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            Ok(TriageOutcome {
                cost_usd: self.0,
                cost_usd_exact: true,
                ..Default::default()
            })
        }
    }

    #[test]
    fn rejects_invalid_provider_costs() {
        for invalid in [-1.0, f64::NAN, f64::INFINITY] {
            let request = AgentQueryRequest::new("model", ".", "system", "prompt");
            assert!(query_blocking_checked(&InvalidCostRuntime(invalid), request).is_err());
        }
    }

    #[test]
    fn rejects_invalid_triage_costs() {
        let request = TriageRequest {
            model: "model".to_string(),
            cwd: ".".into(),
            finding: crate::findings::Finding::new_tool(
                "test",
                "rule",
                "src/lib.rs",
                1,
                None,
                crate::findings::Severity::Low,
                "test",
            ),
            prompt_template: None,
        };
        assert!(
            triage_finding_blocking_checked(&InvalidCostRuntime(f64::INFINITY), request,).is_err()
        );
    }
}
