//! Explicit allowance adapter for the existing inert registry regression.
use super::*;
use crate::allowance::AllowanceBinding;
use crate::runtime::{AgentQueryResponse, RuntimeCost, RuntimeCostReport, TriageRequest};

struct OwnedAllowanceRuntime<'a> {
    inner: &'a dyn AgentRuntime,
    binding: AllowanceBinding,
}

pub(super) fn bind_owned_runtime(
    inner: &dyn AgentRuntime,
    binding: AllowanceBinding,
) -> Box<dyn AgentRuntime + '_> {
    Box::new(OwnedAllowanceRuntime { inner, binding })
}

impl AgentRuntime for OwnedAllowanceRuntime<'_> {
    fn allowance_binding(&self) -> Option<&AllowanceBinding> {
        Some(&self.binding)
    }
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let reservation = self.binding.reserve(&request.model)?;
        let response = self.inner.query_blocking(request)?;
        self.binding
            .settle(reservation, RuntimeCostReport::known(RuntimeCost::ZERO))?;
        Ok(response)
    }
    fn triage_finding_blocking(
        &self,
        request: TriageRequest,
    ) -> Result<crate::findings::TriageOutcome> {
        self.inner.triage_finding_blocking(request)
    }
}

pub(super) fn approved_lift_and_hunt(
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    fingerprint: &str,
) -> (Value, Value) {
    let registry = crate::ModuleRegistry::with_v2_builtins();
    dispatch(
        &registry,
        ctx,
        None,
        "campaign:approve-allowance",
        json!({
        "investigationId":"legacy-owned-variants","expectedRevision":0,"model":"openai:gpt-4.1",
        "maxProviderCalls":3,"protectedReviewCalls":1,"reason":"Owned inert registry regression"}),
    );
    let lift = dispatch(
        &registry,
        ctx,
        Some(runtime),
        "variant:lift-pattern",
        input("F-0001", "draft"),
    );
    let hunt = dispatch(
        &registry,
        ctx,
        Some(runtime),
        "variant:hunt",
        input(fingerprint, "search"),
    );
    (lift, hunt)
}

fn input(fingerprint: &str, work: &str) -> Value {
    json!({"fingerprint":fingerprint,"allowanceRef":{"schemaVersion":1,
        "investigationId":"legacy-owned-variants","revision":1,"workId":work}})
}

pub(super) fn approved_advisory_extraction(
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
) -> Value {
    let registry = crate::ModuleRegistry::with_v2_builtins();
    dispatch(
        &registry,
        ctx,
        None,
        "campaign:approve-allowance",
        json!({
        "investigationId":"owned-advisory-regression","expectedRevision":0,"model":"openai:gpt-4.1",
        "maxProviderCalls":3,"protectedReviewCalls":1,"reason":"Owned inert advisory regression"}),
    );
    dispatch(
        &registry,
        ctx,
        Some(runtime),
        "ndiff:extract-fix-pattern",
        json!({
        "patchText":"--- a/parser.c\n+++ b/parser.c\n+if (len > cap) return -1;\n",
        "allowanceRef":{"schemaVersion":1,"investigationId":"owned-advisory-regression","revision":1,"workId":"draft"}}),
    )
}

pub(super) fn approved_advisory_hunt(
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    pattern: Value,
) -> Value {
    let registry = crate::ModuleRegistry::with_v2_builtins();
    dispatch(
        &registry,
        ctx,
        Some(runtime),
        "ndiff:hunt-variants",
        json!({
        "pattern":pattern,"advisoryId":"CVE-2024-1234","allowanceRef":{"schemaVersion":1,
            "investigationId":"owned-advisory-regression","revision":1,"workId":"search"}}),
    )
}

fn dispatch(
    registry: &crate::ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    tool: &str,
    input: Value,
) -> Value {
    let prepared = registry
        .prepare_dispatch_input(tool, input, ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, ctx, runtime)
        .unwrap()
}
