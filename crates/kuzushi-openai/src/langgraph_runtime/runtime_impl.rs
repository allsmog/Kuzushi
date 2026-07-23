use anyhow::Result;
use async_trait::async_trait;
use kuzushi_core::{
    runtime::RuntimeCostReport, AgentLoopStep, AgentQueryControl, AgentQueryRequest,
    AgentQueryResponse, AgentRuntime, AgentStructuredOutput, AgentToolLoopRequest,
    LoopHistoryEntry, ModelTokenUsage, Observed, ScanCancellation, TriageOutcome, TriageRequest,
};

use super::bridge_payloads::{BridgeRequest, BridgeResponse, LANGGRAPH_BRIDGE_PROTOCOL_VERSION};
use super::bridge_process::{
    public_bridge_error, public_bridge_failure_with_detail, run_bridge,
};
use super::next_step_bridge::next_step_blocking as run_next_step_blocking;
use super::next_step_bridge::next_step_observed_blocking as run_next_step_observed_blocking;
use super::next_step_bridge::preflight_tool_loop_blocking as run_preflight_tool_loop_blocking;
use super::runtime_config::LangGraphRuntime;
use super::transport_retry;
use super::triage::{
    clamp_outcome, normalize_triage_confidence, triage_prompt, triage_system_prompt,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn clamp_token_count_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[async_trait]
impl AgentRuntime for LangGraphRuntime {
    fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.query_observed_blocking(request)
            .map(Observed::into_value)
    }

    fn query_observed_blocking(
        &self,
        request: AgentQueryRequest,
    ) -> Result<Observed<AgentQueryResponse>> {
        let credential = self.credential_for_model(&request.model)?;
        let bridge_request = bridge_request_from(self, request, credential);
        let response = run_bridge_with_transport_retries(
            &self.command,
            bridge_request,
            self.cancellation.as_ref(),
        )?;
        observed_agent_response_from_bridge(response).try_map(AgentQueryResponse::validate_cost)
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
        control.ensure_active()?;
        let local = ScanCancellation::default();
        let done = Arc::new(AtomicBool::new(false));
        let watchdog = spawn_query_control_watchdog(
            local.clone(),
            self.cancellation.clone(),
            control.clone(),
            Arc::clone(&done),
        );
        let result = self
            .clone()
            .with_cancellation(local)
            .query_observed_blocking(request);
        done.store(true, Ordering::SeqCst);
        let _ = watchdog.join();
        control.ensure_active()?;
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
        let prompt = triage_prompt(&request.finding, request.prompt_template.as_deref())?;
        let response = self.query_observed_blocking(
            AgentQueryRequest::new(request.model, request.cwd, triage_system_prompt(), prompt)
                .with_structured_output(triage_structured_output())
                .with_temperature(0.0),
        )?;
        response.try_map(triage_outcome_from_response)
    }

    fn supports_tools(&self) -> bool {
        // Anthropic-only in this version (bridge enforces). Routed
        // queries with non-Anthropic models will surface a clear error
        // from the bridge itself.
        true
    }

    fn next_step_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        run_next_step_blocking(self, request, history)
    }

    fn next_step_observed_blocking(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<Observed<AgentLoopStep>> {
        run_next_step_observed_blocking(self, request, history)
    }

    fn preflight_tool_loop_blocking(&self, request: &AgentToolLoopRequest) -> Result<()> {
        run_preflight_tool_loop_blocking(self, request)
    }
}

fn bridge_request_from(
    runtime: &LangGraphRuntime,
    request: AgentQueryRequest,
    credential: ModelCredential,
) -> BridgeRequest {
    let thinking_level = request
        .thinking_level
        .or_else(|| runtime.thinking_level.clone());
    BridgeRequest {
        protocol_version: LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
        model: request.model,
        cwd: request.cwd.display().to_string(),
        system_prompt: request.system_prompt,
        prompt: request.prompt,
        structured_output: request.structured_output,
        api_key_env: credential.env,
        api_key: credential.value,
        base_url: runtime.base_url.clone(),
        thinking_level,
        max_output_tokens: request.max_output_tokens,
        tool_policy: request.tool_policy,
        runtime_options: request.runtime_options,
        temperature: request.temperature,
    }
}

fn observed_agent_response_from_bridge(response: BridgeResponse) -> Observed<AgentQueryResponse> {
    let usage =
        ModelTokenUsage::from_reported_options(response.input_tokens, response.output_tokens);
    let cost_usd_reported = response.cost_usd.is_some();
    Observed::new(
        AgentQueryResponse {
            text: response.text.unwrap_or_default(),
            structured: response.structured,
            cost_usd: response.cost_usd.unwrap_or(0.0),
            cost_usd_reported,
            estimated_cost_usd: None,
            input_tokens: clamp_token_count_u32(response.input_tokens.unwrap_or(0)),
            output_tokens: clamp_token_count_u32(response.output_tokens.unwrap_or(0)),
            truncated: response.truncated,
            stop_reason: response.stop_reason,
        },
        usage,
    )
}

fn spawn_query_control_watchdog(
    local: ScanCancellation,
    existing: Option<ScanCancellation>,
    control: AgentQueryControl,
    done: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            if control.is_cancelled()
                || control.is_expired()
                || existing
                    .as_ref()
                    .is_some_and(ScanCancellation::is_cancelled)
            {
                local.cancel();
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
    })
}

pub(crate) struct ModelCredential {
    pub(crate) env: String,
    pub(crate) value: Option<String>,
}

impl LangGraphRuntime {
    pub(crate) fn credential_for_model(&self, model: &str) -> Result<ModelCredential> {
        let env = kuzushi_core::runtime::bridge_api_key_env_for_model(model, &self.api_key_env)?;
        let value = if env == self.api_key_env {
            self.api_key.clone()
        } else {
            std::env::var(&env)
                .ok()
                .filter(|value| !value.trim().is_empty())
        };
        Ok(ModelCredential { env, value })
    }
}

fn run_bridge_with_transport_retries(
    command: &[String],
    request: BridgeRequest,
    cancellation: Option<&kuzushi_core::ScanCancellation>,
) -> Result<BridgeResponse> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        ensure_not_cancelled(cancellation)?;
        let (error, failure) =
            match bridge_attempt_outcome(run_bridge(command, &request, cancellation))? {
                BridgeAttempt::Success(response) => return Ok(response),
                BridgeAttempt::Retry { error, failure } => (error, failure),
            };
        if attempt >= transport_retry::max_attempts(&failure) {
            return Err(error);
        }
        transport_retry::sleep_before_retry(transport_retry::backoff_delay(attempt, &failure), || {
            ensure_not_cancelled(cancellation)
        })?;
    }
}

fn ensure_not_cancelled(cancellation: Option<&kuzushi_core::ScanCancellation>) -> Result<()> {
    if cancellation.is_some_and(kuzushi_core::ScanCancellation::is_cancelled) {
        anyhow::bail!("LangGraph bridge cancelled");
    }
    Ok(())
}

enum BridgeAttempt {
    Success(BridgeResponse),
    Retry {
        error: anyhow::Error,
        failure: transport_retry::TransientFailure,
    },
}

fn bridge_attempt_outcome(result: Result<BridgeResponse>) -> Result<BridgeAttempt> {
    match result {
        Ok(response) if response.ok => Ok(BridgeAttempt::Success(response)),
        Ok(response) => bridge_response_error(response),
        Err(error) => bridge_transport_error(error),
    }
}

fn bridge_response_error(response: BridgeResponse) -> Result<BridgeAttempt> {
    let failure = transport_retry::response_transient_failure(
        response.status,
        response.error_class.as_deref(),
        response.error.as_deref(),
        response.retry_after_seconds,
    );
    let message = public_bridge_failure_with_detail(
        response.error_class.as_deref(),
        response.status,
        response.error.as_deref(),
        response.detail.as_deref(),
    );
    let Some(failure) = failure else {
        anyhow::bail!("LangGraph bridge failed: {message}");
    };
    Ok(BridgeAttempt::Retry {
        error: anyhow::anyhow!("LangGraph bridge failed: {message}"),
        failure,
    })
}

fn bridge_transport_error(error: anyhow::Error) -> Result<BridgeAttempt> {
    let message = error.to_string();
    let Some(failure) = transport_retry::message_transient_failure(&message) else {
        anyhow::bail!("{}", public_bridge_error(&message));
    };
    Ok(BridgeAttempt::Retry {
        error: anyhow::anyhow!("{}", public_bridge_error(&message)),
        failure,
    })
}

pub(crate) fn triage_outcome_from_response(response: AgentQueryResponse) -> Result<TriageOutcome> {
    let response = response.validate_cost()?;
    let call_cost = response.checked_cost_report()?;
    if let Some(structured) = response.structured {
        return structured_triage_outcome(structured, call_cost);
    }
    text_triage_outcome(response, call_cost)
}

fn structured_triage_outcome(
    mut structured: serde_json::Value,
    call_cost: RuntimeCostReport,
) -> Result<TriageOutcome> {
    normalize_triage_confidence(&mut structured);
    let mut outcome = serde_json::from_value::<TriageOutcome>(structured)
        .map_err(|_| anyhow::anyhow!("LangGraph triage JSON violated schema"))?;
    apply_call_cost(&mut outcome, call_cost);
    clamp_outcome(outcome).validate_cost()
}

fn text_triage_outcome(
    response: AgentQueryResponse,
    call_cost: RuntimeCostReport,
) -> Result<TriageOutcome> {
    if response.truncated {
        let stop_reason = response.stop_reason.as_deref().unwrap_or("length");
        anyhow::bail!(
            "LangGraph triage response was truncated (stopReason: {stop_reason:?}); refusing to synthesize a verdict"
        );
    }
    let text = response.text.trim();
    if text.is_empty() {
        anyhow::bail!("LangGraph bridge returned no triage content");
    }
    let mut value = serde_json::from_str::<serde_json::Value>(strip_whole_json_fence(text))
        .map_err(|_| anyhow::anyhow!("LangGraph triage response was not valid triage JSON"))?;
    normalize_triage_confidence(&mut value);
    let mut outcome = serde_json::from_value::<TriageOutcome>(value)
        .map_err(|_| anyhow::anyhow!("LangGraph triage response violated triage schema"))?;
    apply_call_cost(&mut outcome, call_cost);
    clamp_outcome(outcome).validate_cost()
}

fn apply_call_cost(outcome: &mut TriageOutcome, call_cost: RuntimeCostReport) {
    outcome.cost_usd = call_cost.observed_usd();
    outcome.cost_usd_exact = call_cost.is_complete();
}

fn strip_whole_json_fence(text: &str) -> &str {
    let Some(without_open) = text.strip_prefix("```") else {
        return text;
    };
    let without_lang = without_open
        .strip_prefix("json")
        .or_else(|| without_open.strip_prefix("JSON"))
        .unwrap_or(without_open)
        .trim_start();
    without_lang
        .strip_suffix("```")
        .map(str::trim)
        .unwrap_or(text)
}

fn triage_structured_output() -> AgentStructuredOutput {
    AgentStructuredOutput::json_schema(
        "kuzushi_triage_outcome",
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["verdict", "confidence", "rationale"],
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["true_positive", "false_positive", "needs_review"]
                },
                "confidence": {
                    "oneOf": [
                        {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        {"type": "string", "enum": ["high", "medium", "low"]}
                    ]
                },
                "rationale": {"type": "string"}
            }
        }),
    )
}
