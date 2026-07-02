use super::*;

pub(crate) fn run_smoke_next_step_tool(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let runtime = smoke_runtime(runtime)?;
    let phrase = smoke_phrase(&input);
    let request = smoke_request(ctx, &phrase)?;
    let parent_step = emit_smoke_next_step_start(ctx);

    let mut toolbox = smoke_toolbox();

    let _loop_scope = begin_smoke_next_step_scope(ctx, parent_step);
    let outcome = crate::runtime::run_tool_loop(runtime, &request, &mut toolbox)?;
    drop(_loop_scope);
    let echoed = outcome.text.contains(&phrase);

    let summary = format!(
        "smoke:next-step completed in {} step{}",
        outcome.steps_used,
        if outcome.steps_used == 1 { "" } else { "s" }
    );
    let data = json!({
        "echoedPhrase": echoed,
        "stepsUsed": outcome.steps_used,
        "truncated": outcome.truncated,
        "costUsd": outcome.cost_usd,
        "transcript": outcome.transcript,
        "finalText": outcome.text,
    });
    let mut result = crate::module_result::completed_output_result(summary.clone(), summary, data);
    result["costUsd"] = json!(outcome.cost_usd);
    emit_smoke_next_step_done(ctx, outcome.steps_used);
    Ok(result)
}

fn emit_smoke_next_step_start(ctx: &ToolExecutionContext<'_>) -> Option<usize> {
    ctx.trace.map(|trace| {
        trace
            .step("tool", "next-step", "smoke:next-step start")
            .emit()
    })
}

fn begin_smoke_next_step_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };
    let phase = trace
        .child(parent)
        .step("reasoning", "next-step", "tool-loop · echo")
        .emit();
    Some(trace.parent_scope(phase))
}

fn emit_smoke_next_step_done(ctx: &ToolExecutionContext<'_>, steps_used: u32) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "next-step",
                format!("smoke:next-step complete · {steps_used} steps"),
            )
            .emit();
    }
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
        anyhow::anyhow!(crate::runtime::missing_agent_runtime_message(
            "smoke:next-step"
        ))
    })?;
    ensure_smoke_tools_supported(runtime)?;
    Ok(runtime)
}

pub(crate) fn ensure_smoke_tools_supported(runtime: &dyn AgentRuntime) -> Result<()> {
    if !runtime.supports_tools() {
        anyhow::bail!(
            "smoke:next-step: configured runtime does not support tools \
             (LangGraphRuntime should — check the bridge configuration)"
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
    use crate::runtime::{AgentLoopStep, AgentToolLoopRequest, LoopHistoryEntry, ToolCall};
    use crate::V2Config;
    use crate::{TriageOutcome, TriageRequest};
    use std::sync::Mutex;

    struct ScriptedSmokeRuntime {
        steps: Mutex<Vec<AgentLoopStep>>,
    }

    impl ScriptedSmokeRuntime {
        fn new(steps: Vec<AgentLoopStep>) -> Self {
            Self {
                steps: Mutex::new(steps),
            }
        }
    }

    impl AgentRuntime for ScriptedSmokeRuntime {
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("smoke test uses tool-loop calls")
        }

        fn supports_tools(&self) -> bool {
            true
        }

        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            _history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            Ok(self.steps.lock().unwrap().remove(0))
        }
    }

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

        assert_eq!(
            smoke_model(&smoke_context(&config)).unwrap(),
            "openai:gpt-5.5"
        );

        config.model = None;
        let err = smoke_model(&smoke_context(&config))
            .unwrap_err()
            .to_string();
        assert!(err.contains("smoke:next-step requires an explicit model"));
    }

    #[test]
    fn smoke_next_step_returns_completed_envelope() {
        let runtime = ScriptedSmokeRuntime::new(vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "echo".to_string(),
                    input: json!({ "x": "kuzushi-ok" }),
                    call_id: "call-1".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "kuzushi-ok".to_string(),
                structured: None,
                cost_usd: Some(0.01),
            },
        ]);
        let config = V2Config {
            model: Some("openai:gpt-5.5".to_string()),
            ..V2Config::default()
        };

        let result =
            run_smoke_next_step_tool(json!({}), &smoke_context(&config), Some(&runtime)).unwrap();

        assert_eq!(
            result.pointer("/status").and_then(Value::as_str),
            Some("completed")
        );
        assert_eq!(
            result
                .pointer("/data/echoedPhrase")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            result.pointer("/costUsd").and_then(Value::as_f64),
            Some(0.01)
        );
    }
}
