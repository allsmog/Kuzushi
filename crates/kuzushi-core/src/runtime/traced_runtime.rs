use super::*;
use crate::run_artifacts::TraceHandle;
use std::time::Instant;

mod metadata;
use metadata::*;
pub use metadata::{
    model_error_class_from_message, model_provider, prompt_pair_hash, safe_model_failure_message,
};

pub struct TracedRuntime<'a> {
    inner: &'a dyn AgentRuntime,
    trace: TraceHandle,
}

struct ModelCallLifecycle {
    call_id: crate::run_lifecycle::RunCallId,
    item_id: crate::run_lifecycle::RunItemId,
}

impl<'a> TracedRuntime<'a> {
    pub fn new(inner: &'a dyn AgentRuntime, trace: TraceHandle) -> Self {
        Self { inner, trace }
    }

    fn record_model_call_start(
        &self,
        verb: &str,
        label: String,
        model: &str,
        prompt_hash: &str,
    ) -> Result<ModelCallLifecycle> {
        let _ = self
            .trace
            .step("tool-progress", verb, label)
            .with_model_metadata(model, model_provider(model), prompt_hash)
            .emit();
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
        prompt_len: usize,
        model: &str,
        prompt_hash: &str,
        result: &Result<Observed<AgentQueryResponse>>,
        elapsed_ms: u64,
        lifecycle: ModelCallLifecycle,
    ) -> Result<()> {
        match result {
            Ok(response) => self.record_successful_query(
                verb,
                prompt_len,
                model,
                prompt_hash,
                &response.value,
                elapsed_ms,
            ),
            Err(error) => self.record_failed_query(verb, model, prompt_hash, error, elapsed_ms),
        }
        let (cost, usage, error_class) = observed_query_telemetry(result);
        self.record_model_call_finish(
            lifecycle,
            model,
            result.is_ok(),
            elapsed_ms,
            usage,
            cost,
            error_class,
        )
    }

    fn record_successful_query(
        &self,
        verb: &str,
        prompt_len: usize,
        model: &str,
        prompt_hash: &str,
        response: &AgentQueryResponse,
        elapsed_ms: u64,
    ) {
        let label = format!("{verb} completed · {prompt_len} chars in");
        let mut step = self
            .trace
            .step("reasoning", verb, label)
            .with_latency_ms(elapsed_ms)
            .with_model_metadata(model, model_provider(model), prompt_hash)
            .with_call_attempted(true);
        if let Ok(cost) = response.checked_cost_report() {
            step = step.with_cost_report(cost);
        }
        let _ = step.emit();
    }

    fn record_failed_query(
        &self,
        verb: &str,
        model: &str,
        prompt_hash: &str,
        error: &anyhow::Error,
        elapsed_ms: u64,
    ) {
        let _ = self
            .trace
            .step("refused", verb, safe_error_label(verb, error))
            .with_latency_ms(elapsed_ms)
            .with_model_metadata(model, model_provider(model), prompt_hash)
            .with_call_attempted(true)
            .with_severity("danger")
            .emit();
    }

    fn record_triage_result(
        &self,
        result: &Result<Observed<TriageOutcome>>,
        model: &str,
        prompt_hash: &str,
        elapsed_ms: u64,
        lifecycle: ModelCallLifecycle,
    ) -> Result<()> {
        match result {
            Ok(outcome) => {
                self.record_successful_triage(&outcome.value, model, prompt_hash, elapsed_ms)
            }
            Err(error) => self.record_failed_triage(error, model, prompt_hash, elapsed_ms),
        }
        let cost = result
            .as_ref()
            .ok()
            .and_then(|outcome| crate::runtime::triage_cost_report(&outcome.value).ok())
            .unwrap_or(crate::runtime::RuntimeCostReport::INCOMPLETE_ZERO);
        let usage = result.as_ref().map_or_else(
            |_| ModelTokenUsage::unavailable_call(),
            |outcome| outcome.usage,
        );
        let error_class = model_call_error_class(result, usage);
        self.record_model_call_finish(
            lifecycle,
            model,
            result.is_ok(),
            elapsed_ms,
            usage,
            cost,
            error_class,
        )
    }

    fn record_successful_triage(
        &self,
        outcome: &TriageOutcome,
        model: &str,
        prompt_hash: &str,
        elapsed_ms: u64,
    ) {
        let mut step = self
            .trace
            .step("reasoning", "triage", "triage completed")
            .with_latency_ms(elapsed_ms)
            .with_model_metadata(model, model_provider(model), prompt_hash)
            .with_call_attempted(true);
        if let Ok(cost) = crate::runtime::triage_cost_report(outcome) {
            step = step.with_cost_report(cost);
        }
        let _ = step.emit();
    }

    fn record_failed_triage(
        &self,
        error: &anyhow::Error,
        model: &str,
        prompt_hash: &str,
        elapsed_ms: u64,
    ) {
        let _ = self
            .trace
            .step("refused", "triage", safe_error_label("triage", error))
            .with_latency_ms(elapsed_ms)
            .with_model_metadata(model, model_provider(model), prompt_hash)
            .with_call_attempted(true)
            .with_severity("danger")
            .emit();
    }

    fn record_step(
        &self,
        result: &Result<Observed<AgentLoopStep>>,
        elapsed_ms: u64,
        history_len: usize,
        model: &str,
        prompt_hash: &str,
        lifecycle: ModelCallLifecycle,
    ) -> Result<()> {
        let provider = model_provider(model);
        self.record_step_trace(
            result,
            elapsed_ms,
            history_len,
            model,
            provider,
            prompt_hash,
        );
        let (cost, usage) = observed_step_telemetry(result);
        let error_class = model_call_error_class(result, usage);
        self.record_model_call_finish(
            lifecycle,
            model,
            result.is_ok(),
            elapsed_ms,
            usage,
            cost,
            error_class,
        )
    }

    fn record_step_trace(
        &self,
        result: &Result<Observed<AgentLoopStep>>,
        elapsed_ms: u64,
        history_len: usize,
        model: &str,
        provider: &str,
        prompt_hash: &str,
    ) {
        match result {
            Ok(Observed {
                value: AgentLoopStep::ToolCall { call, cost_usd },
                ..
            }) => self.record_tool_call_step(
                call,
                *cost_usd,
                elapsed_ms,
                history_len,
                model,
                provider,
                prompt_hash,
            ),
            Ok(Observed {
                value: AgentLoopStep::Final { cost_usd, .. },
                ..
            }) => self.record_final_step(
                *cost_usd,
                elapsed_ms,
                history_len,
                model,
                provider,
                prompt_hash,
            ),
            Err(error) => {
                self.record_step_error(error, elapsed_ms, model, provider, prompt_hash);
            }
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
    ) -> Result<()> {
        let Some(observation) = self.trace.run_observation() else {
            return Ok(());
        };
        observation.emit(
            crate::run_lifecycle::RunItemRecord::new(
                lifecycle.item_id,
                crate::run_lifecycle::RunItemSource::Runtime,
                crate::run_lifecycle::RunItemV1::ModelCallFinished {
                    provider: crate::run_lifecycle::SafeText::operator_visible(model_provider(
                        model,
                    )),
                    model: crate::run_lifecycle::SafeText::operator_visible(model),
                    status: if succeeded {
                        crate::run_lifecycle::RunItemStatus::Completed
                    } else {
                        crate::run_lifecycle::RunItemStatus::Failed
                    },
                    latency_ms,
                    usage: persisted_model_usage(usage),
                    cost,
                    error_class: error_class.map(crate::run_lifecycle::SafeText::operator_visible),
                },
            )
            .with_call(lifecycle.call_id),
        )
    }

    fn record_tool_call_step(
        &self,
        call: &ToolCall,
        cost_usd: Option<f64>,
        elapsed_ms: u64,
        history_len: usize,
        model: &str,
        provider: &str,
        prompt_hash: &str,
    ) {
        let mut step = self
            .trace
            .step(
                "tool-progress",
                "next-step",
                tool_call_label(call, history_len),
            )
            .with_latency_ms(elapsed_ms)
            .with_model_metadata(model, provider, prompt_hash)
            .with_call_attempted(true);
        if let Some(cost) = cost_usd {
            step = step.with_cost_usd(cost);
        }
        let _ = step.emit();
    }

    fn record_final_step(
        &self,
        cost_usd: Option<f64>,
        elapsed_ms: u64,
        history_len: usize,
        model: &str,
        provider: &str,
        prompt_hash: &str,
    ) {
        let mut step = self
            .trace
            .step("done", "next-step", final_label(history_len))
            .with_latency_ms(elapsed_ms)
            .with_model_metadata(model, provider, prompt_hash)
            .with_call_attempted(true);
        if let Some(cost) = cost_usd {
            step = step.with_cost_usd(cost);
        }
        let _ = step.emit();
    }

    fn record_step_error(
        &self,
        error: &anyhow::Error,
        elapsed_ms: u64,
        model: &str,
        provider: &str,
        prompt_hash: &str,
    ) {
        let _ = self
            .trace
            .step("refused", "next-step", safe_error_label("step", error))
            .with_latency_ms(elapsed_ms)
            .with_model_metadata(model, provider, prompt_hash)
            .with_call_attempted(true)
            .with_severity("danger")
            .emit();
    }
}

fn model_call_error_class<T>(result: &Result<T>, usage: ModelTokenUsage) -> Option<&'static str> {
    match result {
        Err(error) => Some(model_error_class(error)),
        Ok(_) if !usage.is_complete() && !usage.is_unavailable() => {
            Some("usage_incomplete_lower_bound")
        }
        Ok(_) => None,
    }
}

fn observed_step_telemetry(
    result: &Result<Observed<AgentLoopStep>>,
) -> (crate::runtime::RuntimeCostReport, ModelTokenUsage) {
    let cost = result
        .as_ref()
        .ok()
        .and_then(|step| step.value.checked_cost_report().ok())
        .unwrap_or(crate::runtime::RuntimeCostReport::INCOMPLETE_ZERO);
    let usage = result
        .as_ref()
        .map_or_else(|_| ModelTokenUsage::unavailable_call(), |step| step.usage);
    (cost, usage)
}

fn observed_query_telemetry(
    result: &Result<Observed<AgentQueryResponse>>,
) -> (
    crate::runtime::RuntimeCostReport,
    ModelTokenUsage,
    Option<&'static str>,
) {
    let cost = result
        .as_ref()
        .ok()
        .and_then(|response| response.value.checked_cost_report().ok())
        .unwrap_or(crate::runtime::RuntimeCostReport::INCOMPLETE_ZERO);
    let usage = result.as_ref().map_or_else(
        |_| ModelTokenUsage::unavailable_call(),
        |response| response.usage,
    );
    (cost, usage, model_call_error_class(result, usage))
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
        let prompt_hash = prompt_pair_hash(&request.system_prompt, &request.prompt);
        let lifecycle = self.record_model_call_start(
            "query",
            format!("query · sending {prompt_len} chars"),
            &model,
            &prompt_hash,
        )?;
        let result = self
            .inner
            .query_observed_blocking(request)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost));
        self.record_query(
            "query",
            prompt_len,
            &model,
            &prompt_hash,
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
        let prompt_hash = prompt_pair_hash(&request.system_prompt, &request.prompt);
        let lifecycle = self.record_model_call_start(
            "query",
            format!("query · sending {prompt_len} chars"),
            &model,
            &prompt_hash,
        )?;
        let result = self
            .inner
            .query_observed_blocking_controlled(request, control)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost));
        self.record_query(
            "query",
            prompt_len,
            &model,
            &prompt_hash,
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
            .triage_finding_observed_blocking(request)
            .and_then(|observed| observed.try_map(TriageOutcome::validate_cost));
        self.record_triage_result(
            &result,
            &model,
            &prompt_hash,
            start.elapsed().as_millis() as u64,
            lifecycle,
        )?;
        result
    }

    fn supports_tools(&self) -> bool {
        self.inner.supports_tools()
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
            .next_step_observed_blocking(request, history)
            .and_then(|observed| observed.try_map(AgentLoopStep::validate_cost));
        self.record_step(
            &result,
            start.elapsed().as_millis() as u64,
            history.len(),
            &model,
            &prompt_hash,
            lifecycle,
        )?;
        result
    }

    fn preflight_tool_loop_blocking(&self, request: &AgentToolLoopRequest) -> Result<()> {
        let start = Instant::now();
        let model = request.model.clone();
        let prompt_hash = prompt_pair_hash(&request.system_prompt, &request.prompt);
        let provider = model_provider(&model);
        let result = self.inner.preflight_tool_loop_blocking(request);
        let elapsed_ms = start.elapsed().as_millis() as u64;
        match &result {
            Ok(()) => {
                let _ = self
                    .trace
                    .step("tool-progress", "next-step", "tool-loop preflight ok")
                    .with_latency_ms(elapsed_ms)
                    .with_model_metadata(&model, provider, &prompt_hash)
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
                    .with_latency_ms(elapsed_ms)
                    .with_model_metadata(&model, provider, &prompt_hash)
                    .with_severity("danger")
                    .emit();
            }
        }
        result
    }

    fn model_for_tier(&self, tier: ModelTier, configured: &str) -> String {
        self.inner.model_for_tier(tier, configured)
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
        let lifecycle = self.record_model_call_start(
            verb,
            format!("{verb} · sending {prompt_len} chars"),
            &model,
            &prompt_hash,
        )?;
        let result = self
            .inner
            .spawn_subagent_observed_blocking(role, request)
            .and_then(|observed| observed.try_map(AgentQueryResponse::validate_cost));
        self.record_query(
            verb,
            prompt_len,
            &model,
            &prompt_hash,
            &result,
            start.elapsed().as_millis() as u64,
            lifecycle,
        )?;
        result
    }
}

#[cfg(test)]
mod tests;
