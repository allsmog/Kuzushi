//! Native Anthropic tool-augmented loop.
//!
//! Closes the parity gap between `AnthropicOAuthRuntime` and the LangGraph
//! bridge: the bridge's `next-step` envelope runs one round-trip of the
//! Anthropic Messages tool-use API and returns either a `tool_call` or a
//! `final`. This module reproduces that single-step contract natively so the
//! shared agent driver (`AgentRuntime::next_step_blocking`) can execute the
//! tools between turns exactly as it does against the bridge.
//!
//! The step boundary is deliberately identical to
//! `langgraph_runtime::next_step_bridge`: build the request from
//! `system_prompt` + `prompt` + running `history` + `tools`, POST it once,
//! and map the response to a single `AgentLoopStep`. The driver owns the loop
//! and tool execution; this module never executes a tool itself.

use anyhow::{Context, Result};
use kuzushi_core::{AgentLoopStep, AgentToolLoopRequest, LoopHistoryEntry, ToolCall};
use serde_json::{json, Value};

use super::client::{ensure_anthropic_success, read_anthropic_response_body};
use super::options::AnthropicOAuthRuntime;
use super::response::{
    anthropic_response_text, anthropic_response_tool_use, anthropic_response_usage,
    estimate_cost_usd, maybe_parse_json, strip_provider_prefix, ApiResponse,
};
use crate::messages::build_messages_for_anthropic;

impl AnthropicOAuthRuntime {
    /// One tool-loop round-trip. Talks to the model with `request.tools` and
    /// the running `history`; returns a `ToolCall` for the driver to execute
    /// or a `Final` answer. Does not execute tools.
    pub(crate) async fn run_tool_loop_step(
        &self,
        request: &AgentToolLoopRequest,
        history: &[LoopHistoryEntry],
    ) -> Result<AgentLoopStep> {
        let model = strip_provider_prefix(&request.model);
        let body = anthropic_tool_loop_body(&model, self.max_tokens, request, history);
        let resp = self.send_anthropic_messages_request(&body).await?;
        let status = resp.status();
        let raw = read_anthropic_response_body(resp).await?;
        ensure_anthropic_success(status, &raw)?;
        parse_tool_loop_response(&model, &raw)
    }
}

/// Build the Anthropic `/v1/messages` request body for one tool-loop step.
///
/// Mirrors the bridge's `NextStepBridgeRequest`: `tools` are forwarded
/// verbatim (`name`/`description`/`input_schema`), and the conversation is
/// `initial prompt + history` rendered by `build_messages_for_anthropic`
/// (the same renderer the bridge path uses), so a native step and a bridge
/// step send the model the same transcript.
pub(crate) fn anthropic_tool_loop_body(
    model: &str,
    max_tokens: u32,
    request: &AgentToolLoopRequest,
    history: &[LoopHistoryEntry],
) -> Value {
    let tools: Vec<Value> = request
        .tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            })
        })
        .collect();
    let mut body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "system": request.system_prompt,
        "messages": build_messages_for_anthropic(&request.prompt, history),
        "tools": tools,
    });
    if let Some(temperature) = request.temperature {
        body["temperature"] = json!(temperature);
    }
    body
}

/// Map one Anthropic Messages response to an `AgentLoopStep`. A response
/// carrying a `tool_use` block becomes a `ToolCall`; otherwise the joined
/// text (plus best-effort embedded JSON) becomes a `Final`. Per-round cost is
/// surfaced on both so the driver settles spend incrementally.
pub(crate) fn parse_tool_loop_response(model: &str, raw: &str) -> Result<AgentLoopStep> {
    let parsed: ApiResponse = serde_json::from_str(raw)
        .with_context(|| format!("Anthropic OAuth tool loop: could not parse response: {raw}"))?;
    let (input_tokens, output_tokens) = anthropic_response_usage(&parsed);
    let cost_usd = Some(estimate_cost_usd(model, input_tokens, output_tokens));

    if let Some((id, name, input)) = anthropic_response_tool_use(&parsed) {
        return Ok(AgentLoopStep::ToolCall {
            call: ToolCall {
                name: name.to_string(),
                input: input.clone(),
                call_id: id.to_string(),
            },
            cost_usd,
        });
    }

    let text = anthropic_response_text(&parsed);
    let structured = maybe_parse_json(&text);
    Ok(AgentLoopStep::Final {
        text,
        structured,
        cost_usd,
    })
}
