use super::*;
use crate::findings::FindingStore;
use std::path::Path;

pub(in crate::modules) fn run_verify_finding(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "verify:finding",
        ))?;
    let store = ctx
        .findings_store
        .context("verify:finding requires a findings store for the active workspace")?;

    let fingerprint = input
        .get("fingerprint")
        .or_else(|| input.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let parent_step = emit_verify_start(ctx, fingerprint);
    emit_verify_progress(ctx, parent_step, "finding · load evidence and context");

    let result =
        run_scoped_verify_finding(input, ctx, runtime, workspace.root(), store, parent_step);
    emit_verify_done(ctx, &result);
    result
}

fn run_scoped_verify_finding(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    workspace_root: &Path,
    store: &FindingStore,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
) -> Result<Value> {
    let _verify_scope = begin_verify_scope(ctx, parent_step);
    let result = crate::verification::adapters::run_verify_finding_tool(
        crate::verification::adapters::VerifyFindingToolRequest {
            input,
            workspace_root,
            store,
            runtime,
            configured_model: ctx.config.model.as_deref(),
            trace: ctx.trace,
        },
    );
    drop(_verify_scope);
    result
}

fn emit_verify_start(ctx: &ToolExecutionContext<'_>, fingerprint: &str) -> Option<crate::run_lifecycle::RunItemId> {
    ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                "finding",
                format!("verify start · fp={fingerprint}"),
            )
            .emit()
    })
}

fn emit_verify_progress(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
    label: impl Into<String>,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };
    let _ = trace
        .child(parent)
        .step("tool-progress", "finding", label.into())
        .emit();
}

fn begin_verify_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<crate::run_lifecycle::RunItemId>,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };
    let phase = trace
        .child(parent)
        .step("reasoning", "finding", "exploitability check")
        .emit();
    Some(trace.parent_scope(phase))
}

fn emit_verify_done(ctx: &ToolExecutionContext<'_>, result: &Result<Value>) {
    let (Some(trace), Ok(output)) = (ctx.trace, result) else {
        return;
    };
    let status = output
        .get("data")
        .and_then(|data| data.get("verdict").or_else(|| data.get("status")))
        .and_then(Value::as_str)
        .unwrap_or("complete");
    let _ = trace
        .step("done", "finding", format!("verify · {status}"))
        .emit();
}

pub(in crate::modules) fn run_verify_exploit(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "verify:exploit",
        ))?;
    let store = ctx
        .findings_store
        .context("verify:exploit requires a findings store for the active workspace")?;

    crate::verification::adapters::run_verify_exploit_tool_for_run(
        input,
        workspace.root(),
        store,
        ctx.run_id(),
    )
}
