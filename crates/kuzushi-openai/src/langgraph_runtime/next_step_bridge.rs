use anyhow::{Context, Result};
use kuzushi_core::{AgentLoopStep, AgentToolLoopRequest, LoopHistoryEntry, ToolCall};

use super::bridge_payloads::{
    BridgeTool, NextStepBridgeRequest, NextStepBridgeResponse, LANGGRAPH_BRIDGE_PROTOCOL_VERSION,
};
use super::bridge_process::{
    public_bridge_error, run_next_step_bridge, run_next_step_preflight_bridge,
};
use super::runtime_config::LangGraphRuntime;
use crate::messages::build_messages_for_anthropic;

pub(crate) fn next_step_blocking(
    runtime: &LangGraphRuntime,
    request: &AgentToolLoopRequest,
    history: &[LoopHistoryEntry],
) -> Result<AgentLoopStep> {
    validate_runtime_model(runtime, &request.model)?;
    let bridge_request = next_step_bridge_request(runtime, request, history);
    // Same transient-retry policy as query_blocking: without it, one 429 or
    // dropped socket kills an entire multi-step agent loop mid-flight. A
    // next-step call is a pure model query, so retrying is safe.
    const ATTEMPTS: usize = 3;
    let mut last_error: Option<anyhow::Error> = None;
    for attempt in 1..=ATTEMPTS {
        ensure_not_cancelled(runtime)?;
        match run_next_step_bridge(
            &runtime.command,
            &bridge_request,
            runtime.cancellation.as_ref(),
        )
        .and_then(ensure_next_step_response_ok)
        {
            Ok(step) => return Ok(step),
            Err(error) => {
                if attempt == ATTEMPTS
                    || !super::runtime_impl::is_transient_bridge_error(&error.to_string())
                {
                    return Err(error);
                }
                last_error = Some(error);
            }
        }
        ensure_not_cancelled(runtime)?;
        std::thread::sleep(std::time::Duration::from_millis(
            super::runtime_impl::retry_delay_ms(attempt),
        ));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("next-step bridge failed")))
}

pub(crate) fn preflight_tool_loop_blocking(
    runtime: &LangGraphRuntime,
    request: &AgentToolLoopRequest,
) -> Result<()> {
    validate_runtime_model(runtime, &request.model)?;
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
        api_key_env: credential.env,
        api_key: credential.value,
        base_url: runtime.base_url.clone(),
        runtime_options: request.runtime_options.clone(),
        temperature: request.temperature,
    }
}

fn ensure_next_step_response_ok(response: NextStepBridgeResponse) -> Result<AgentLoopStep> {
    if !response.ok {
        let message = response
            .error
            .unwrap_or_else(|| "unknown error".to_string());
        anyhow::bail!(
            "LangGraph next-step bridge failed: {}",
            public_bridge_error(&message)
        );
    }
    step_from_bridge_response(response)
}

fn ensure_next_step_preflight_ok(response: NextStepBridgeResponse) -> Result<()> {
    if response.ok {
        return Ok(());
    }
    let message = response
        .error
        .unwrap_or_else(|| "unknown error".to_string());
    anyhow::bail!(
        "LangGraph next-step preflight failed: {}",
        public_bridge_error(&message)
    )
}

fn step_from_bridge_response(response: NextStepBridgeResponse) -> Result<AgentLoopStep> {
    match response.step.as_deref() {
        Some("tool_call") => tool_call_step(response),
        Some("final") => Ok(AgentLoopStep::Final {
            text: response.text.unwrap_or_default(),
            structured: response.structured,
            cost_usd: response.cost_usd,
        }),
        other => anyhow::bail!(
            "next-step bridge returned unexpected step: {:?}",
            other.unwrap_or("(missing)")
        ),
    }
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
