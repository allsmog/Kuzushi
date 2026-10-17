//! Finite ledger accounting for scripted requests. Callers supply inert runtimes.
use super::{
    AgentLoopStep, AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolLoopRequest,
    AgentToolPolicyAuthorization, AgentToolPolicyReceipt, LoopHistoryEntry, TriageRequest,
};
use crate::allowance::{
    AllowanceApprovalV1, AllowanceBinding, AllowanceLimits, AllowanceWork, InvestigationWork,
};
use crate::{SpendLimiter, ToolExecutionContext};
use anyhow::Result;
use std::sync::Arc;

pub(crate) struct AccountedScriptedRuntime<'a> {
    inner: &'a dyn AgentRuntime,
    binding: AllowanceBinding,
}

pub(crate) fn account_scripted_runtime<'a>(
    ctx: &ToolExecutionContext<'_>,
    inner: &'a dyn AgentRuntime,
    category: InvestigationWork,
    calls: u32,
) -> AccountedScriptedRuntime<'a> {
    let model = ctx.config.model.as_deref().expect("explicit fixture model");
    account_scripted_model_runtime(ctx, inner, model, category, calls)
}

pub(crate) fn account_scripted_model_runtime<'a>(
    ctx: &ToolExecutionContext<'_>,
    inner: &'a dyn AgentRuntime,
    model: &str,
    category: InvestigationWork,
    calls: u32,
) -> AccountedScriptedRuntime<'a> {
    let workspace = ctx.workspace.expect("scripted fixture workspace");
    let ledger = Arc::new(SpendLimiter::open(workspace.findings_db_path()).unwrap());
    let id = format!("scripted-runtime-fixture-{}", uuid::Uuid::new_v4().simple());
    approve_scripted_requests(&ledger, &id, model, calls);
    let work = AllowanceWork {
        investigation_id: id,
        revision: 1,
        run_id: ctx
            .run_id()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        work_id: "scripted-request".into(),
        model: model.into(),
        work: category,
    };
    AccountedScriptedRuntime {
        inner,
        binding: AllowanceBinding::new(ledger, work).unwrap(),
    }
}

fn approve_scripted_requests(ledger: &SpendLimiter, id: &str, model: &str, calls: u32) {
    ledger
        .approve_allowance(&AllowanceApprovalV1 {
            schema_version: 1,
            investigation_id: id.into(),
            expected_revision: 0,
            model: model.into(),
            limits: AllowanceLimits {
                max_provider_calls: calls,
                protected_review_calls: 0,
            },
            reason: "Explicit scripted fixture; no provider transport".into(),
            work_plan: None,
        })
        .unwrap();
}

impl AgentRuntime for AccountedScriptedRuntime<'_> {
    fn allowance_binding(&self) -> Option<&AllowanceBinding> {
        Some(&self.binding)
    }

    fn preflight_model_blocking(&self, model: &str) -> Result<()> {
        self.binding.validate_model(model)?;
        self.inner.preflight_model_blocking(model)
    }

    fn preflight_tool_loop_blocking(&self, request: &AgentToolLoopRequest) -> Result<()> {
        self.binding.validate_model(&request.model)?;
        self.inner.preflight_tool_loop_blocking(request)
    }

    fn authorize_tool_policy_blocking(
        &self,
        authorization: &AgentToolPolicyAuthorization,
    ) -> Result<AgentToolPolicyReceipt> {
        self.inner.authorize_tool_policy_blocking(authorization)
    }

    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let reservation = self.binding.reserve(&request.model)?;
        let response = self.inner.query_blocking(request)?;
        self.binding
            .settle(reservation, response.checked_cost_report()?)?;
        Ok(response)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<crate::TriageOutcome> {
        let reservation = self.binding.reserve(&request.model)?;
        let response = self.inner.triage_finding_blocking(request)?;
        self.binding
            .settle(reservation, super::triage_cost_report(&response)?)?;
        Ok(response)
    }

    fn supports_tools(&self) -> bool {
        self.inner.supports_tools()
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        let reservation = self.binding.reserve(&request.model)?;
        let response = self.inner.next_step_blocking(request, history)?;
        self.binding
            .settle(reservation, response.checked_cost_report()?)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
