use super::*;
use crate::run_artifacts::TraceHandle;
use std::time::Instant;

mod metadata;
use metadata::*;
pub use metadata::{model_provider, prompt_pair_hash};

pub struct TracedRuntime<'a> {
    inner: &'a dyn AgentRuntime,
    trace: TraceHandle,
}

impl<'a> TracedRuntime<'a> {
    pub fn new(inner: &'a dyn AgentRuntime, trace: TraceHandle) -> Self {
        Self { inner, trace }
    }

    fn record_query(
        &self,
        verb: &str,
        prompt_len: usize,
        model: &str,
        prompt_hash: &str,
        result: &Result<AgentQueryResponse>,
        elapsed_ms: u64,
    ) {
        let provider = model_provider(model);
        match result {
            Ok(response) => {
                let preview = preview_text(&response.text);
                let label = if preview.is_empty() {
                    format!("{verb} · {prompt_len} chars in")
                } else {
                    format!("{verb} · {preview}")
                };
                let mut step = self
                    .trace
                    .step("reasoning", verb, label)
                    .with_latency_ms(elapsed_ms)
                    .with_model_metadata(model, provider, prompt_hash);
                if response.cost_usd > 0.0 {
                    step = step.with_cost_usd(response.cost_usd);
                }
                let _ = step.emit();
            }
            Err(error) => {
                let _ = self
                    .trace
                    .step("refused", verb, format!("{verb} failed: {error}"))
                    .with_latency_ms(elapsed_ms)
                    .with_model_metadata(model, provider, prompt_hash)
                    .with_severity("danger")
                    .emit();
            }
        }
    }

    fn record_step(
        &self,
        result: &Result<AgentLoopStep>,
        elapsed_ms: u64,
        history_len: usize,
        model: &str,
        prompt_hash: &str,
    ) {
        let provider = model_provider(model);
        match result {
            Ok(AgentLoopStep::ToolCall { call }) => self.record_tool_call_step(
                call,
                elapsed_ms,
                history_len,
                model,
                provider,
                prompt_hash,
            ),
            Ok(AgentLoopStep::Final { text, cost_usd, .. }) => self.record_final_step(
                text,
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

    fn record_tool_call_step(
        &self,
        call: &ToolCall,
        elapsed_ms: u64,
        history_len: usize,
        model: &str,
        provider: &str,
        prompt_hash: &str,
    ) {
        let _ = self
            .trace
            .step("tool-progress", "next-step", tool_call_label(call, history_len))
            .with_latency_ms(elapsed_ms)
            .with_model_metadata(model, provider, prompt_hash)
            .emit();
    }

    fn record_final_step(
        &self,
        text: &str,
        cost_usd: Option<f64>,
        elapsed_ms: u64,
        history_len: usize,
        model: &str,
        provider: &str,
        prompt_hash: &str,
    ) {
        let mut step = self
            .trace
            .step("done", "next-step", final_label(text, history_len))
            .with_latency_ms(elapsed_ms)
            .with_model_metadata(model, provider, prompt_hash);
        if let Some(cost) = cost_usd.filter(|cost| *cost > 0.0) {
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
            .step("refused", "next-step", format!("step failed: {error}"))
            .with_latency_ms(elapsed_ms)
            .with_model_metadata(model, provider, prompt_hash)
            .with_severity("danger")
            .emit();
    }
}

#[async_trait]
impl AgentRuntime for TracedRuntime<'_> {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        let start = Instant::now();
        let prompt_len = request.prompt.len();
        let model = request.model.clone();
        let prompt_hash = prompt_pair_hash(&request.system_prompt, &request.prompt);
        let result = self.inner.query_blocking(request);
        self.record_query(
            "query",
            prompt_len,
            &model,
            &prompt_hash,
            &result,
            start.elapsed().as_millis() as u64,
        );
        result
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome> {
        let start = Instant::now();
        let model = request.model.clone();
        let prompt_hash = triage_prompt_hash(&request);
        let title = request.finding.title.clone();
        let result = self.inner.triage_finding_blocking(request);
        let elapsed_ms = start.elapsed().as_millis() as u64;
        let provider = model_provider(&model);
        match &result {
            Ok(_) => {
                let _ = self
                    .trace
                    .step(
                        "reasoning",
                        "triage",
                        format!("triage · {}", preview_str(&title)),
                    )
                    .with_latency_ms(elapsed_ms)
                    .with_model_metadata(&model, provider, &prompt_hash)
                    .emit();
            }
            Err(error) => {
                let _ = self
                    .trace
                    .step("refused", "triage", format!("triage failed: {error}"))
                    .with_latency_ms(elapsed_ms)
                    .with_model_metadata(&model, provider, &prompt_hash)
                    .with_severity("danger")
                    .emit();
            }
        }
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
        let start = Instant::now();
        let model = request.model.clone();
        let prompt_hash = prompt_pair_hash(&request.system_prompt, &request.prompt);
        let result = self.inner.next_step_blocking(request, history);
        self.record_step(
            &result,
            start.elapsed().as_millis() as u64,
            history.len(),
            &model,
            &prompt_hash,
        );
        result
    }

    fn preflight_tool_loop_blocking(&self, request: &AgentToolLoopRequest) -> Result<()> {
        let start = Instant::now();
        let result = self.inner.preflight_tool_loop_blocking(request);
        let elapsed_ms = start.elapsed().as_millis() as u64;
        match &result {
            Ok(()) => {
                let _ = self
                    .trace
                    .step("tool-progress", "next-step", "tool-loop preflight ok")
                    .with_latency_ms(elapsed_ms)
                    .emit();
            }
            Err(error) => {
                let _ = self
                    .trace
                    .step(
                        "refused",
                        "next-step",
                        format!("tool-loop preflight failed: {error}"),
                    )
                    .with_latency_ms(elapsed_ms)
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
        let start = Instant::now();
        let prompt_len = request.prompt.len();
        let model = request.model.clone();
        let prompt_hash = prompt_pair_hash(&request.system_prompt, &request.prompt);
        let result = self.inner.spawn_subagent_blocking(role, request);
        let verb = subagent_trace_verb(role);
        self.record_query(
            verb,
            prompt_len,
            &model,
            &prompt_hash,
            &result,
            start.elapsed().as_millis() as u64,
        );
        result
    }
}

#[cfg(test)]
mod tests;
