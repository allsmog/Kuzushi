use super::*;
use crate::run_artifacts::TraceHandle;
use std::time::Instant;

mod metadata;
use metadata::*;
pub use metadata::{
    model_error_class_from_message, model_provider, prompt_pair_hash, safe_model_failure_message,
};

pub struct TracedRuntime<'a> {
    inner: InnerRuntime<'a>,
    trace: TraceHandle,
    /// Every model call's cost report, summed. Engines that reduce spend to
    /// an `(observed, exact)` pair lose the token estimate; the dispatch
    /// boundary recovers it from here.
    spend: std::sync::Arc<std::sync::Mutex<crate::runtime::RuntimeCostReport>>,
}

enum InnerRuntime<'a> {
    Borrowed(&'a dyn AgentRuntime),
    Bound(Box<dyn AgentRuntime + 'a>),
}

impl InnerRuntime<'_> {
    fn get(&self) -> &dyn AgentRuntime {
        match self {
            Self::Borrowed(runtime) => *runtime,
            Self::Bound(runtime) => runtime.as_ref(),
        }
    }
}

#[derive(Clone, Copy)]
struct ModelCallLifecycle {
    call_id: crate::run_lifecycle::RunCallId,
    item_id: crate::run_lifecycle::RunItemId,
}

impl<'a> TracedRuntime<'a> {
    pub fn new(inner: &'a dyn AgentRuntime, trace: TraceHandle) -> Self {
        Self {
            inner: InnerRuntime::Borrowed(inner),
            trace,
            spend: std::sync::Arc::new(std::sync::Mutex::new(
                crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO),
            )),
        }
    }

    /// Spend of every model call made through this runtime so far.
    pub fn observed_spend(&self) -> crate::runtime::RuntimeCostReport {
        self.spend
            .lock()
            .map_or(crate::runtime::RuntimeCostReport::UNAVAILABLE, |spend| {
                *spend
            })
    }

    /// An arithmetic failure keeps the observed floor but drops the estimate.
    fn tally_call_cost(&self, cost: crate::runtime::RuntimeCostReport) {
        if let Ok(mut spend) = self.spend.lock() {
            *spend = spend
                .checked_add(cost, "traced runtime spend")
                .unwrap_or_else(|_| spend.mark_incomplete());
        }
    }

    fn record_model_call_start(
        &self,
        _verb: &str,
        _label: String,
        model: &str,
        prompt_hash: &str,
    ) -> Result<ModelCallLifecycle> {
        let lifecycle = ModelCallLifecycle {
            call_id: crate::run_lifecycle::RunCallId::new(),
            item_id: crate::run_lifecycle::RunItemId::new(),
        };
        if let Some(observation) = self.trace.run_observation() {
            observation.emit_and_flush(
                crate::run_lifecycle::RunItemRecord::new(
                    lifecycle.item_id,
                    crate::run_lifecycle::RunItemSource::Runtime,
                    crate::run_lifecycle::RunItemV1::ModelCallStarted {
                        provider: crate::run_lifecycle::SafeText::operator_visible(model_provider(
                            model,
                        )),
                        model: crate::run_lifecycle::SafeText::operator_visible(model),
                        operation_fingerprint:
                            crate::run_lifecycle::OperationFingerprint::from_bytes(
                                prompt_hash.as_bytes(),
                            ),
                    },
                )
                .with_call(lifecycle.call_id),
            )?;
        }
        Ok(lifecycle)
    }

    fn record_query(
        &self,
        verb: &str,
        stage: &str,
        model: &str,
        result: &Result<Observed<AgentQueryResponse>>,
        elapsed_ms: u64,
        lifecycle: ModelCallLifecycle,
    ) -> Result<()> {
        if let Err(error) = result {
            self.record_failed_query(verb, error);
        }
        let (cost, usage) = observed_query_telemetry(result);
        let failure = model_call_failure(result, lifecycle, stage);
        let error_class = model_call_error_class(result, usage, failure.as_ref());
        self.record_model_call_finish(
            lifecycle,
            model,
            result.is_ok(),
            elapsed_ms,
            usage,
            cost,
            error_class,
            failure,
        )
    }

    fn record_failed_query(&self, verb: &str, error: &anyhow::Error) {
        let _ = self
            .trace
            .step("refused", verb, safe_error_label(verb, error))
            .with_severity("danger")
            .emit();
    }

    fn record_triage_result(
        &self,
        result: &Result<Observed<TriageOutcome>>,
        model: &str,
        elapsed_ms: u64,
        lifecycle: ModelCallLifecycle,
    ) -> Result<()> {
        if let Err(error) = result {
            self.record_failed_triage(error);
        }
        let cost = result
            .as_ref()
            .ok()
            .and_then(|outcome| crate::runtime::triage_cost_report(&outcome.value).ok())
            .unwrap_or_else(|| failed_call_cost(result));
        let usage = result.as_ref().map_or_else(
            |_| ModelTokenUsage::unavailable_call(),
            |outcome| outcome.usage,
        );
        let failure = model_call_failure(result, lifecycle, "triage");
        let error_class = model_call_error_class(result, usage, failure.as_ref());
        self.record_model_call_finish(
            lifecycle,
            model,
            result.is_ok(),
            elapsed_ms,
            usage,
            cost,
            error_class,
            failure,
        )
    }

    fn record_failed_triage(&self, error: &anyhow::Error) {
        let _ = self
            .trace
            .step("refused", "triage", safe_error_label("triage", error))
            .with_severity("danger")
            .emit();
    }

    fn record_step(
        &self,
        result: &Result<Observed<AgentLoopStep>>,
        elapsed_ms: u64,
        history_len: usize,
        model: &str,
        lifecycle: ModelCallLifecycle,
    ) -> Result<()> {
        self.record_step_trace(result, history_len);
        let (cost, usage) = observed_step_telemetry(result);
        let failure = model_call_failure(result, lifecycle, "next-step");
        let error_class = model_call_error_class(result, usage, failure.as_ref());
        self.record_model_call_finish(
            lifecycle,
            model,
            result.is_ok(),
            elapsed_ms,
            usage,
            cost,
            error_class,
            failure,
        )
    }

    fn record_step_trace(&self, result: &Result<Observed<AgentLoopStep>>, history_len: usize) {
        match result {
            Ok(Observed {
                value: AgentLoopStep::ToolCall { call, cost_usd: _ },
                ..
            }) => self.record_tool_call_step(call, history_len),
            Ok(Observed {
                value: AgentLoopStep::Final { cost_usd: _, .. },
                ..
            }) => self.record_final_step(history_len),
            Err(error) => self.record_step_error(error),
        }
    }

    fn record_model_call_finish(
        &self,
        lifecycle: ModelCallLifecycle,
        model: &str,
        succeeded: bool,
        latency_ms: u64,
        usage: ModelTokenUsage,
        cost: crate::runtime::RuntimeCostReport,
        error_class: Option<&'static str>,
        failure: Option<crate::runtime::RuntimeFailureMetadata>,
    ) -> Result<()> {
        self.tally_call_cost(cost);
        let Some(observation) = self.trace.run_observation() else {
            return Ok(());
        };
        let summary =
            succeeded.then(|| self.record_model_response_summary(&observation, lifecycle));
        observation.emit_and_flush(
            crate::run_lifecycle::RunItemRecord::new(
                lifecycle.item_id,
                crate::run_lifecycle::RunItemSource::Runtime,
                crate::run_lifecycle::RunItemV1::ModelCallFinished {
                    provider: crate::run_lifecycle::SafeText::operator_visible(model_provider(
                        model,
                    )),
                    model: crate::run_lifecycle::SafeText::operator_visible(model),
                    status: model_call_status(succeeded),
                    latency_ms,
                    usage: persisted_model_usage(usage),
                    cost,
                    error_class: error_class.map(crate::run_lifecycle::SafeText::operator_visible),
                    failure,
                },
            )
            .with_call(lifecycle.call_id),
        )?;
        summary.transpose().map(|_| ())
    }

    fn record_model_response_summary(
        &self,
        observation: &crate::run_lifecycle::RunObservationHandle,
        lifecycle: ModelCallLifecycle,
    ) -> Result<()> {
        observation
            .for_call_progress(lifecycle.call_id, lifecycle.item_id)
            .with_parent(lifecycle.item_id)
            .emit_coalescible(crate::run_lifecycle::RunItemRecord::new(
                crate::run_lifecycle::RunItemId::new(),
                crate::run_lifecycle::RunItemSource::Runtime,
                crate::run_lifecycle::RunItemV1::SafeReasoningSummary {
                    text: crate::run_lifecycle::SafeText::operator_visible(
                        "Model response received",
                    ),
                    redaction_policy_version:
                        crate::run_lifecycle::RUN_ITEM_REDACTION_POLICY_VERSION,
                },
            ))
            .map(drop)
    }

    fn record_tool_call_step(&self, call: &ToolCall, history_len: usize) {
        let _ = self
            .trace
            .step(
                "tool-progress",
                "next-step",
                tool_call_label(call, history_len),
            )
            .emit();
    }

    fn record_final_step(&self, history_len: usize) {
        let _ = self
            .trace
            .step("done", "next-step", final_label(history_len))
            .emit();
    }

    fn record_step_error(&self, error: &anyhow::Error) {
        let _ = self
            .trace
            .step("refused", "next-step", safe_error_label("step", error))
            .with_severity("danger")
            .emit();
    }
}

fn model_call_status(succeeded: bool) -> crate::run_lifecycle::RunItemStatus {
    if succeeded {
        crate::run_lifecycle::RunItemStatus::Completed
    } else {
        crate::run_lifecycle::RunItemStatus::Failed
    }
}

fn model_call_error_class<T>(
    result: &Result<T>,
    usage: ModelTokenUsage,
    failure: Option<&crate::runtime::RuntimeFailureMetadata>,
) -> Option<&'static str> {
    match result {
        Err(_) => failure.map(|failure| failure.error_class.as_str()),
        Ok(_) if !usage.is_complete() && !usage.is_unavailable() => {
            Some("usage_incomplete_lower_bound")
        }
        Ok(_) => None,
    }
}

fn model_call_failure<T>(
    result: &Result<T>,
    lifecycle: ModelCallLifecycle,
    stage: &str,
) -> Option<crate::runtime::RuntimeFailureMetadata> {
    let error = result.as_ref().err()?;
    let metadata = model_failure_metadata(error);
    Some(metadata.with_model_call(lifecycle.call_id, Some(stage)))
}

/// Preserve typed runtime failures across application boundaries, with a
/// bounded category-only projection for legacy errors. Never retain raw text.
pub fn model_failure_metadata(error: &anyhow::Error) -> crate::runtime::RuntimeFailureMetadata {
    crate::runtime::runtime_failure_metadata(error)
        .unwrap_or_else(|| fallback_runtime_failure_metadata(error))
}

fn fallback_runtime_failure_metadata(
    error: &anyhow::Error,
) -> crate::runtime::RuntimeFailureMetadata {
    use crate::runtime::{RuntimeFailureClass as Class, RuntimeFailureMetadata};
    let legacy = model_error_class(error);
    let class = match legacy {
        "canceled" => Class::Cancelled,
        "invalid_response" => Class::ProviderResponseInvalid,
        other => Class::from_safe_class(other),
    };
    RuntimeFailureMetadata::new(class, None, None)
}

fn observed_step_telemetry(
    result: &Result<Observed<AgentLoopStep>>,
) -> (crate::runtime::RuntimeCostReport, ModelTokenUsage) {
    let cost = result
        .as_ref()
        .ok()
        .and_then(|step| step.value.checked_cost_report().ok())
        .unwrap_or_else(|| failed_call_cost(result));
    let usage = result
        .as_ref()
        .map_or_else(|_| ModelTokenUsage::unavailable_call(), |step| step.usage);
    (cost, usage)
}

fn observed_query_telemetry(
    result: &Result<Observed<AgentQueryResponse>>,
) -> (crate::runtime::RuntimeCostReport, ModelTokenUsage) {
    let cost = result
        .as_ref()
        .ok()
        .and_then(|response| response.value.checked_cost_report().ok())
        .unwrap_or_else(|| failed_call_cost(result));
    let usage = result.as_ref().map_or_else(
        |_| ModelTokenUsage::unavailable_call(),
        |response| response.usage,
    );
    (cost, usage)
}

fn failed_call_cost<T>(result: &Result<T>) -> crate::runtime::RuntimeCostReport {
    let mcp_unavailable = result
        .as_ref()
        .err()
        .and_then(crate::runtime::runtime_failure_metadata)
        .is_some_and(|failure| {
            failure.error_class == crate::runtime::RuntimeFailureClass::McpUnavailable
        });
    if mcp_unavailable {
        crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO)
    } else {
        crate::runtime::RuntimeCostReport::INCOMPLETE_ZERO
    }
}

fn persisted_model_usage(usage: ModelTokenUsage) -> crate::run_lifecycle::ModelUsage {
    let (input_tokens, output_tokens) = usage.observed_counts();
    crate::run_lifecycle::ModelUsage {
        input_tokens,
        output_tokens,
    }
}

#[async_trait]
impl AgentRuntime for TracedRuntime<'_> {
    fn authorize_tool_policy_blocking(
        &self,
        authorization: &crate::runtime::AgentToolPolicyAuthorization,
    ) -> Result<crate::runtime::AgentToolPolicyReceipt> {
        self.inner
            .get()
            .authorize_tool_policy_blocking(authorization)
    }

    fn with_allowance_binding(
        &self,
        allowance: crate::allowance::AllowanceBinding,
    ) -> Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(TracedRuntime {
            inner: InnerRuntime::Bound(self.inner.get().with_allowance_binding(allowance)?),
            trace: self.trace.clone(),
            spend: self.spend.clone(),
        }))
    }

    fn semantic_cache_identity(
        &self,
        request: &AgentQueryRequest,
    ) -> Option<crate::identity::Blake3Hash> {
        self.inner.get().semantic_cache_identity(request)
    }

    fn preflight_model_blocking(&self, model: &str) -> Result<()> {
        self.inner.get().preflight_model_blocking(model)
    }

    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.query_observed_blocking(request)
            .map(Observed::into_value)
    }

    fn query_observed_blocking(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        let start = Instant::now();
        let prompt_len = request.prompt.len();
        let model = request.model.clone();
        let stage = request.stage.clone().unwrap_or_else(|| "query".to_string());
        let prompt_hash = prompt_pair_hash(&request.system_prompt, &request.prompt);
        let lifecycle = self.record_model_call_start(
            "query",
            format!("query · sending {prompt_len} chars"),
            &model,
            &prompt_hash,
        )?;
        let result = self
            .inner
            .get()
            .query_observed_blocking(request)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost));
        self.record_query(
            "query",
            &stage,
            &model,
            &result,
            start.elapsed().as_millis() as u64,
            lifecycle,
        )?;
        result
    }

    fn query_blocking_controlled(
        &self,
        request: AgentQueryRequest,
        control: AgentQueryControl,
    ) -> Result<AgentQueryResponse> {
        self.query_observed_blocking_controlled(request, control)
            .map(Observed::into_value)
    }

    fn query_observed_blocking_controlled(
        &self,
        request: AgentQueryRequest,
        control: AgentQueryControl,
    ) -> Result<Observed<AgentQueryResponse>> {
        let start = Instant::now();
        let prompt_len = request.prompt.len();
        let model = request.model.clone();
        let stage = request.stage.clone().unwrap_or_else(|| "query".to_string());
        let prompt_hash = prompt_pair_hash(&request.system_prompt, &request.prompt);
        let lifecycle = self.record_model_call_start(
            "query",
            format!("query · sending {prompt_len} chars"),
            &model,
            &prompt_hash,
        )?;
        let result = self
            .inner
            .get()
            .query_observed_blocking_controlled(request, control)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost));
        self.record_query(
            "query",
            &stage,
            &model,
            &result,
            start.elapsed().as_millis() as u64,
            lifecycle,
        )?;
        result
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.triage_finding_observed_blocking(request)
            .map(Observed::into_value)
    }

    fn triage_finding_observed_blocking(
        &self,
        request: TriageRequest,
    ) -> Result<Observed<TriageOutcome>> {
        let start = Instant::now();
        let model = request.model.clone();
        let prompt_hash = triage_prompt_hash(&request);
        let lifecycle = self.record_model_call_start(
            "triage",
            "triage · checking finding".to_string(),
            &model,
            &prompt_hash,
        )?;
        let result = self
            .inner
            .get()
            .triage_finding_observed_blocking(request)
            .and_then(|observed| observed.try_map(TriageOutcome::validate_cost));
        self.record_triage_result(
            &result,
            &model,
            start.elapsed().as_millis() as u64,
            lifecycle,
        )?;
        result
    }

    fn supports_tools(&self) -> bool {
        self.inner.get().supports_tools()
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        self.next_step_observed_blocking(request, history)
            .map(Observed::into_value)
    }

    fn next_step_observed_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<Observed<AgentLoopStep>> {
        let start = Instant::now();
        let model = request.model.clone();
        let prompt_hash = prompt_pair_hash(&request.system_prompt, &request.prompt);
        let lifecycle = self.record_model_call_start(
            "next-step",
            format!("next-step · waiting on model (turn {})", history.len() + 1),
            &model,
            &prompt_hash,
        )?;
        let result = self
            .inner
            .get()
            .next_step_observed_blocking(request, history)
            .and_then(|observed| observed.try_map(AgentLoopStep::validate_cost));
        self.record_step(
            &result,
            start.elapsed().as_millis() as u64,
            history.len(),
            &model,
            lifecycle,
        )?;
        result
    }

    fn preflight_tool_loop_blocking(&self, request: &AgentToolLoopRequest) -> Result<()> {
        let result = self.inner.get().preflight_tool_loop_blocking(request);
        match &result {
            Ok(()) => {
                let _ = self
                    .trace
                    .step("tool-progress", "next-step", "tool-loop preflight ok")
                    .emit();
            }
            Err(error) => {
                let _ = self
                    .trace
                    .step(
                        "refused",
                        "next-step",
                        safe_error_label("tool-loop preflight", &error),
                    )
                    .with_severity("danger")
                    .emit();
            }
        }
        result
    }

    fn model_for_tier(&self, tier: ModelTier, configured: &str) -> String {
        self.inner.get().model_for_tier(tier, configured)
    }

    fn spawn_subagent_blocking(
        &self,
        role: SubagentRole,
        request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        self.spawn_subagent_observed_blocking(role, request)
            .map(Observed::into_value)
    }

    fn spawn_subagent_observed_blocking(
        &self,
        role: SubagentRole,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        let start = Instant::now();
        let prompt_len = request.prompt.len();
        let model = request.model.clone();
        let prompt_hash = prompt_pair_hash(&request.system_prompt, &request.prompt);
        let verb = subagent_trace_verb(role);
        let stage = request.stage.clone().unwrap_or_else(|| verb.to_string());
        let lifecycle = self.record_model_call_start(
            verb,
            format!("{verb} · sending {prompt_len} chars"),
            &model,
            &prompt_hash,
        )?;
        let result = self
            .inner
            .get()
            .spawn_subagent_observed_blocking(role, request)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost));
        self.record_query(
            verb,
            &stage,
            &model,
            &result,
            start.elapsed().as_millis() as u64,
            lifecycle,
        )?;
        result
    }
}

#[cfg(test)]
mod tests;
