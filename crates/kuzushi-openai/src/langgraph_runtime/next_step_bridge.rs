use anyhow::{Context, Result};
use kuzushi_core::{
    AgentLoopStep, AgentToolLoopRequest, LoopHistoryEntry, ModelTokenUsage, Observed, ToolCall,
};

use super::bridge_payloads::{
    BridgeTool, NextStepBridgeRequest, NextStepBridgeResponse, LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
};
use super::bridge_process::{
    bridge_runtime_failure, run_next_step_bridge_observed, run_next_step_preflight_bridge,
};
use super::runtime_config::LangGraphRuntime;
use super::transport_retry;
use crate::messages::build_messages_for_anthropic;

pub(crate) fn next_step_blocking(
    runtime: &LangGraphRuntime,
    request: &AgentToolLoopRequest,
    history: &[LoopHistoryEntry],
) -> Result<AgentLoopStep> {
    next_step_observed_blocking(runtime, request, history).map(Observed::into_value)
}

pub(crate) fn next_step_observed_blocking(
    runtime: &LangGraphRuntime,
    request: &AgentToolLoopRequest,
    history: &[LoopHistoryEntry],
) -> Result<Observed<AgentLoopStep>> {
    validate_runtime_model(runtime, &request.model)?;
    let bridge_request = next_step_bridge_request(runtime, request, history);
    // Same transient-retry policy as query_blocking: without it, one 429 or
    // dropped socket kills an entire multi-step agent loop mid-flight. A
    // next-step call is a pure model query, so retrying is safe.
    let mut attempt = 0;
    loop {
        attempt += 1;
        ensure_not_cancelled(runtime)?;
        let outcome = run_next_step_bridge_observed(
            &runtime.command,
            &bridge_request,
            runtime.cancellation.as_ref(),
            runtime.response_text.as_ref(),
        );
        let failure = next_step_transient_failure(&outcome);
        let error = match outcome.and_then(ensure_next_step_response_ok) {
            Ok(step) => return Ok(step),
            Err(error) => error,
        };
        let Some(failure) =
            failure.filter(|f| attempt < transport_retry::max_attempts(f, &runtime.retry))
        else {
            return Err(error);
        };
        transport_retry::sleep_before_retry(
            transport_retry::backoff_delay(attempt, &failure, &runtime.retry),
            || ensure_not_cancelled(runtime),
        )?;
    }
}

/// A retryable next-step failure, classified from the structured response
/// fields when the bridge answered, or from the transport message when the
/// bridge process itself failed. `None` (including an `ok` response that
/// later fails shape validation) is permanent.
fn next_step_transient_failure(
    outcome: &Result<NextStepBridgeResponse>,
) -> Option<transport_retry::TransientFailure> {
    match outcome {
        Ok(response) if !response.ok => transport_retry::response_transient_failure(
            response.status,
            response.error_class.as_deref(),
            response.error.as_deref(),
            response.retry_after_seconds,
        ),
        Ok(_) => None,
        Err(error) => transport_retry::message_transient_failure(&error.to_string()),
    }
}

pub(crate) fn preflight_tool_loop_blocking(
    runtime: &LangGraphRuntime,
    request: &AgentToolLoopRequest,
) -> Result<()> {
    runtime.validated_model_credential(&request.model)?;
    let mut bridge_request = next_step_bridge_request(runtime, request, &[]);
    bridge_request.envelope_type = "next-step-preflight";
    let response = run_next_step_preflight_bridge(
        &runtime.command,
        &bridge_request,
        runtime.cancellation.as_ref(),
    )?;
    ensure_next_step_preflight_ok(response)
}

fn validate_runtime_model(runtime: &LangGraphRuntime, model: &str) -> Result<()> {
    runtime.credential_for_model(model).map(|_| ())
}

fn ensure_not_cancelled(runtime: &LangGraphRuntime) -> Result<()> {
    if runtime
        .cancellation
        .as_ref()
        .is_some_and(kuzushi_core::ScanCancellation::is_cancelled)
    {
        anyhow::bail!("LangGraph next-step bridge cancelled");
    }
    Ok(())
}

fn next_step_bridge_request(
    runtime: &LangGraphRuntime,
    request: &AgentToolLoopRequest,
    history: &[LoopHistoryEntry],
) -> NextStepBridgeRequest {
    let credential = runtime
        .credential_for_model(&request.model)
        .expect("model credential was checked before building bridge request");
    NextStepBridgeRequest {
        protocol_version: LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
        envelope_type: "next-step",
        model: request.model.clone(),
        cwd: request.cwd.display().to_string(),
        system_prompt: request.system_prompt.clone(),
        messages: build_messages_for_anthropic(&request.prompt, history),
        tools: request
            .tools
            .iter()
            .map(|tool| BridgeTool {
                name: tool.name.clone(),
                description: tool.description.clone(),
                input_schema: tool.input_schema.clone(),
            })
            .collect(),
        max_tokens: 4096,
        thinking_level: runtime.thinking_level.clone(),
        api_key_env: credential.env,
        api_key: credential.value,
        oauth_credentials_path: runtime.oauth_credentials_path.display().to_string(),
        oauth_allow_env_token: runtime.oauth_allow_env_token,
        base_url: runtime.base_url.clone(),
        runtime_options: request.runtime_options.clone(),
        temperature: request.temperature,
    }
}

fn ensure_next_step_response_ok(
    response: NextStepBridgeResponse,
) -> Result<Observed<AgentLoopStep>> {
    if !response.ok {
        return Err(bridge_runtime_failure(
            response.error_class.as_deref(),
            response.status,
            response.error.as_deref(),
            response.detail.as_deref(),
        ));
    }
    step_from_bridge_response(response)
}

fn ensure_next_step_preflight_ok(response: NextStepBridgeResponse) -> Result<()> {
    if response.ok {
        return Ok(());
    }
    Err(bridge_runtime_failure(
        response.error_class.as_deref(),
        response.status,
        response.error.as_deref(),
        response.detail.as_deref(),
    ))
}

fn step_from_bridge_response(response: NextStepBridgeResponse) -> Result<Observed<AgentLoopStep>> {
    let usage =
        ModelTokenUsage::from_reported_options(response.input_tokens, response.output_tokens);
    let step = match response.step.as_deref() {
        Some("tool_call") => tool_call_step(response),
        Some("final") => Ok(AgentLoopStep::Final {
            text: response
                .text
                .context("next-step: final step missing text")?,
            structured: response.structured,
            cost_usd: response.cost_usd,
        }),
        other => anyhow::bail!(
            "next-step bridge returned unexpected step: {:?}",
            other.unwrap_or("(missing)")
        ),
    }?;
    step.validate_cost()
        .map(|value| Observed::new(value, usage))
}

fn tool_call_step(response: NextStepBridgeResponse) -> Result<AgentLoopStep> {
    let cost_usd = response.cost_usd;
    let call = response
        .call
        .context("next-step: tool_call missing call body")?;
    Ok(AgentLoopStep::ToolCall {
        call: ToolCall {
            name: call.name,
            input: call.input,
            call_id: call.call_id,
        },
        // The bridge reports per-round cost on tool-call turns too; forward it
        // so the driver settles spend incrementally instead of only at Final.
        cost_usd,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn final_response(input: Option<u64>, output: Option<u64>) -> NextStepBridgeResponse {
        serde_json::from_value(serde_json::json!({
            "ok": true,
            "step": "final",
            "text": "done",
            "input_tokens": input,
            "output_tokens": output
        }))
        .unwrap()
    }

    #[test]
    fn reported_zero_usage_is_not_treated_as_unavailable() {
        let observed = step_from_bridge_response(final_response(Some(0), Some(0))).unwrap();

        assert_eq!(observed.usage.observed_counts(), (Some(0), Some(0)));
        assert!(observed.usage.is_complete());
    }

    #[test]
    fn missing_usage_stays_unavailable() {
        let observed = step_from_bridge_response(final_response(None, None)).unwrap();

        assert_eq!(observed.usage.observed_counts(), (None, None));
        assert!(observed.usage.is_unavailable());
    }
}

#[cfg(test)]
mod reasoning_tests;
