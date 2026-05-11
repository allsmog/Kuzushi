use super::*;

pub(crate) fn run_smoke_next_step_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    use crate::runtime::{run_tool_loop, AgentTool, AgentToolLoopRequest};

    let runtime = smoke_runtime(runtime)?;
    let phrase = input
        .get("phrase")
        .and_then(Value::as_str)
        .unwrap_or("kuzushi-ok")
        .to_string();

    let request = AgentToolLoopRequest {
        model: smoke_model(ctx),
        cwd: std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        system_prompt: "You are participating in a Kuzushi smoke test. \
                        Call the `echo` tool exactly once with input {{ \"x\": <phrase> }}, \
                        then return the echoed text as your final answer."
            .to_string(),
        prompt: format!(
            "Phrase to echo: {phrase}\n\nUse the echo tool, then reply with the result."
        ),
        tools: vec![AgentTool {
            name: "echo".to_string(),
            description: "Returns its input under the key `out` verbatim.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "x": { "type": "string" } },
                "required": ["x"]
            }),
        }],
        max_steps: 4,
        runtime_options: None,
    };

    let mut toolbox = smoke_toolbox();

    let outcome = run_tool_loop(runtime, &request, &mut toolbox)?;
    let echoed = outcome.text.contains(&phrase);

    Ok(json!({
        "ok": true,
        "data": {
            "echoedPhrase": echoed,
            "stepsUsed": outcome.steps_used,
            "truncated": outcome.truncated,
            "costUsd": outcome.cost_usd,
            "transcript": outcome.transcript,
            "finalText": outcome.text,
        },
    }))
}

pub(crate) fn smoke_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    let runtime = runtime.ok_or_else(|| {
        anyhow::anyhow!("smoke:next-step requires an agent runtime; none configured")
    })?;
    ensure_smoke_tools_supported(runtime)?;
    Ok(runtime)
}

pub(crate) fn ensure_smoke_tools_supported(runtime: &dyn AgentRuntime) -> Result<()> {
    if !runtime.supports_tools() {
        anyhow::bail!(
            "smoke:next-step: configured runtime does not support tools \
             (PiAgentCoreRuntime should — check the bridge configuration)"
        );
    }
    Ok(())
}

pub(crate) fn smoke_model(ctx: &ToolExecutionContext<'_>) -> String {
    ctx.config
        .model
        .clone()
        .unwrap_or_else(|| "anthropic:claude-haiku-4-5".to_string())
}

pub(crate) fn smoke_toolbox() -> crate::runtime::ToolBox {
    use crate::runtime::{ToolBox, ToolResult};

    let mut toolbox = ToolBox::new();
    toolbox.register("echo", |call| {
        let x = call
            .input
            .get("x")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(ToolResult {
            call_id: call.call_id.clone(),
            output: json!({ "out": x }),
            is_error: false,
        })
    });
    toolbox
}
