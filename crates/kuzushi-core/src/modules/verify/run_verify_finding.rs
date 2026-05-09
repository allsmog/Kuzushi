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

    crate::verification::adapters::run_verify_finding_tool(
        crate::verification::adapters::VerifyFindingToolRequest {
            input,
            workspace_root: workspace.root(),
            store,
            runtime,
            configured_model: ctx.config.model.as_deref(),
        },
    )
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
