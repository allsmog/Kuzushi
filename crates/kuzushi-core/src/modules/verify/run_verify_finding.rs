use super::*;

pub(in crate::modules) fn run_verify_finding(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx.workspace.context(
        "verify:finding needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("verify:finding requires a findings store for the active workspace")?;

    let fingerprint = input
        .get("fingerprint")
        .or_else(|| input.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "finding",
                format!("verify start · fp={fingerprint}"),
            )
            .emit();
    }

    let result = crate::verification::adapters::run_verify_finding_tool(
        crate::verification::adapters::VerifyFindingToolRequest {
            input,
            workspace_root: workspace.root(),
            store,
            runtime,
            configured_model: ctx.config.model.as_deref(),
        },
    );
    if let Some(trace) = ctx.trace {
        if let Ok(output) = &result {
            let status = output
                .get("data")
                .and_then(|data| data.get("verdict").or_else(|| data.get("status")))
                .and_then(Value::as_str)
                .unwrap_or("complete");
            let _ = trace
                .step("done", "finding", format!("verify · {status}"))
                .emit();
        }
    }
    result
}

pub(in crate::modules) fn run_verify_exploit(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    ctx.workspace.context(
        "verify:exploit needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )?;
    let store = ctx
        .findings_store
        .context("verify:exploit requires a findings store for the active workspace")?;

    crate::verification::adapters::run_verify_exploit_tool(input, store)
}
