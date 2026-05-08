use super::prelude::*;
use super::*;

pub fn run_tool_loop(
    runtime: &dyn AgentRuntime,
    request: &AgentToolLoopRequest,
    handler: &mut dyn ToolCallHandler,
) -> Result<AgentLoopOutcome> {
    if !runtime.supports_tools() {
        anyhow::bail!(
            "runtime does not support tool-augmented loops (set supports_tools() = true \
             and implement next_step_blocking)"
        );
    }

    let mut transcript: Vec<LoopHistoryEntry> = Vec::new();
    let mut cost_usd = 0.0f64;

    let cap = request.max_steps.max(1);
    for step in 0..cap {
        let outcome = runtime
            .next_step_blocking(request, &transcript)
            .with_context(|| format!("agent loop step {step} failed"))?;
        match outcome {
            AgentLoopStep::ToolCall { call } => {
                transcript.push(LoopHistoryEntry::AssistantToolCall(call.clone()));
                let result = handler.run(&call).unwrap_or_else(|err| ToolResult {
                    call_id: call.call_id.clone(),
                    output: serde_json::json!({ "error": err.to_string() }),
                    is_error: true,
                });
                transcript.push(LoopHistoryEntry::ToolResult(result));
            }
            AgentLoopStep::Final {
                text,
                structured,
                cost_usd: step_cost,
            } => {
                if let Some(c) = step_cost {
                    cost_usd += c;
                }
                if !text.is_empty() {
                    transcript.push(LoopHistoryEntry::AssistantText(text.clone()));
                }
                return Ok(AgentLoopOutcome {
                    text,
                    structured,
                    steps_used: step + 1,
                    truncated: false,
                    cost_usd,
                    transcript,
                });
            }
        }
    }

    // Hit max_steps without a Final.
    Ok(AgentLoopOutcome {
        text: String::new(),
        structured: None,
        steps_used: cap,
        truncated: true,
        cost_usd,
        transcript,
    })
}
