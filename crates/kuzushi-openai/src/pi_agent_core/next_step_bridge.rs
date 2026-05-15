use anyhow::{Context, Result};
use kuzushi_core::{AgentLoopStep, AgentToolLoopRequest, LoopHistoryEntry, ToolCall};

use super::bridge_payloads::{BridgeTool, NextStepBridgeRequest, NextStepBridgeResponse};
use super::bridge_process::{run_next_step_bridge, run_next_step_preflight_bridge};
use super::runtime_config::PiAgentCoreRuntime;
use crate::messages::build_messages_for_anthropic;

pub(crate) fn next_step_blocking(
    runtime: &PiAgentCoreRuntime,
    request: &AgentToolLoopRequest,
    history: &[LoopHistoryEntry],
) -> Result<AgentLoopStep> {
    let bridge_request = next_step_bridge_request(runtime, request, history);
    let response = run_next_step_bridge(&runtime.command, &bridge_request)?;
    ensure_next_step_response_ok(response)
}

pub(crate) fn preflight_tool_loop_blocking(
    runtime: &PiAgentCoreRuntime,
    request: &AgentToolLoopRequest,
) -> Result<()> {
    let mut bridge_request = next_step_bridge_request(runtime, request, &[]);
    bridge_request.envelope_type = "next-step-preflight";
    let response = run_next_step_preflight_bridge(&runtime.command, &bridge_request)?;
    ensure_next_step_preflight_ok(response)
}

fn next_step_bridge_request(
    runtime: &PiAgentCoreRuntime,
    request: &AgentToolLoopRequest,
    history: &[LoopHistoryEntry],
) -> NextStepBridgeRequest {
    NextStepBridgeRequest {
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
        api_key_env: runtime.api_key_env.clone(),
        api_key: runtime.api_key.clone(),
        base_url: runtime.base_url.clone(),
        runtime_options: request.runtime_options.clone(),
        temperature: request.temperature,
    }
}

fn ensure_next_step_response_ok(response: NextStepBridgeResponse) -> Result<AgentLoopStep> {
    if !response.ok {
        anyhow::bail!(
            "pi-agent-core next-step bridge failed: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        );
    }
    step_from_bridge_response(response)
}

fn ensure_next_step_preflight_ok(response: NextStepBridgeResponse) -> Result<()> {
    if response.ok {
        return Ok(());
    }
    anyhow::bail!(
        "pi-agent-core next-step preflight failed: {}",
        response
            .error
            .unwrap_or_else(|| "unknown error".to_string())
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
    let call = response
        .call
        .context("next-step: tool_call missing call body")?;
    Ok(AgentLoopStep::ToolCall {
        call: ToolCall {
            name: call.name,
            input: call.input,
            call_id: call.call_id,
        },
    })
}
