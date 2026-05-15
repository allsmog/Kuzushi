use super::*;

pub(crate) fn run_smoke_next_step_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let runtime = smoke_runtime(runtime)?;
    let phrase = smoke_phrase(&input);
    let request = smoke_request(ctx, &phrase)?;

    let mut toolbox = smoke_toolbox();

    let outcome = crate::runtime::run_tool_loop(runtime, &request, &mut toolbox)?;
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

fn smoke_phrase(input: &Value) -> String {
    input
        .get("phrase")
        .and_then(Value::as_str)
        .unwrap_or("kuzushi-ok")
        .to_string()
}

fn smoke_request(
    ctx: &ToolExecutionContext<'_>,
    phrase: &str,
) -> Result<crate::runtime::AgentToolLoopRequest> {
    use crate::runtime::{AgentTool, AgentToolLoopRequest};

    Ok(AgentToolLoopRequest {
        model: smoke_model(ctx)?,
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
        temperature: None,
    })
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

pub(crate) fn smoke_model(ctx: &ToolExecutionContext<'_>) -> Result<String> {
    crate::runtime::require_configured_model("smoke:next-step", ctx.config.model.as_deref())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::V2Config;

    fn smoke_context(config: &V2Config) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config,
            workspace: None,
            findings_store: None,
            trace: None,
        }
    }

    #[test]
    fn smoke_model_uses_configured_model_without_fallback() {
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-5.5".to_string());

        assert_eq!(smoke_model(&smoke_context(&config)).unwrap(), "openai:gpt-5.5");

        config.model = None;
        let err = smoke_model(&smoke_context(&config)).unwrap_err().to_string();
        assert!(err.contains("smoke:next-step requires an explicit model"));
    }
}
