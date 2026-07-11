use crate::capabilities::uaf_hunt::adapters::clang_subprocess::ClangMcpClient;
use crate::capabilities::uaf_hunt::adapters::parse_uaf_hunt_input;
use crate::capabilities::uaf_hunt::application::{
    build_uaf_hunt_user_prompt, persist_uaf_hunt_findings, uaf_hunt_agent_tools,
    UAF_HUNT_SYSTEM_PROMPT,
};
use crate::capabilities::uaf_hunt::domain::{UafHuntInput, UafHuntReport};
use crate::modules::ToolExecutionContext;
use crate::runtime::{run_tool_loop, AgentLoopOutcome, AgentRuntime, AgentToolLoopRequest};
use crate::WorkspaceTarget;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

use super::extract_findings::extract_findings;
use super::toolbox::{build_uaf_hunt_toolbox, new_clang_call_stats, snapshot_clang_call_stats};

pub fn run_uaf_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<UafHuntReport> {
    let run = prepare_uaf_hunt_run(input, ctx, runtime)?;
    let loop_outcome = run_uaf_hunt_agent_loop(ctx, &run)?;
    finish_uaf_hunt_run(ctx, &run, loop_outcome)
}

struct UafHuntRun<'a> {
    target: PathBuf,
    options: UafHuntInput,
    runtime: &'a dyn AgentRuntime,
    request: AgentToolLoopRequest,
    parent_step: Option<usize>,
}

struct UafHuntLoopOutcome {
    outcome: AgentLoopOutcome,
    stats: super::toolbox::ClangCallStats,
}

fn prepare_uaf_hunt_run<'a>(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<UafHuntRun<'a>> {
    let target = resolve_target(input, ctx)?;
    let options = parse_uaf_hunt_input(input, &target)?;
    let parent_step = emit_uaf_hunt_start(ctx, &target);
    emit_uaf_hunt_progress(
        ctx,
        parent_step,
        "input · parsed compile database and agent budget",
    );
    let runtime = require_runtime(runtime)?;
    if !runtime.supports_tools() {
        emit_uaf_hunt_child(
            ctx,
            parent_step,
            "refused",
            "runtime does not support tool-augmented loops",
        );
        anyhow::bail!(
            "uaf-hunt:hunt: configured runtime does not support tool-augmented loops. \
             LangGraphRuntime is required; check the bridge configuration."
        );
    }

    let request = build_loop_request(&target, &options, ctx)?;
    emit_uaf_hunt_progress(ctx, parent_step, "agent · preflight tool loop");
    runtime
        .preflight_tool_loop_blocking(&request)
        .context("uaf-hunt: agent tool-loop preflight failed")?;
    Ok(UafHuntRun {
        target,
        options,
        runtime,
        request,
        parent_step,
    })
}

fn run_uaf_hunt_agent_loop(
    ctx: &ToolExecutionContext<'_>,
    run: &UafHuntRun<'_>,
) -> Result<UafHuntLoopOutcome> {
    let target = &run.target;
    let options = &run.options;
    let parent_step = run.parent_step;
    emit_uaf_hunt_progress(ctx, parent_step, "clang · spawn MCP helper");
    let mut clang = ClangMcpClient::spawn(&target, &options.compile_commands_path)?;
    let clang_stats = new_clang_call_stats();
    let toolbox = build_uaf_hunt_toolbox(&target, &options, &mut clang, clang_stats.clone());
    let mut handler = toolbox;
    let _agent_scope = begin_uaf_hunt_agent_scope(ctx, parent_step);
    let outcome = run_tool_loop(run.runtime, &run.request, &mut handler)
        .context("uaf-hunt: agent tool-loop failed")?;
    drop(_agent_scope);
    let stats = snapshot_clang_call_stats(&clang_stats);
    Ok(UafHuntLoopOutcome { outcome, stats })
}

fn finish_uaf_hunt_run(
    ctx: &ToolExecutionContext<'_>,
    run: &UafHuntRun<'_>,
    loop_outcome: UafHuntLoopOutcome,
) -> Result<UafHuntReport> {
    let stats = loop_outcome.stats;
    let outcome = loop_outcome.outcome;
    let parent_step = run.parent_step;
    emit_uaf_hunt_progress(
        ctx,
        parent_step,
        format!("clang · {} tool calls", stats.calls),
    );
    let findings = extract_findings(&outcome, &run.options)?;
    emit_uaf_hunt_progress(
        ctx,
        parent_step,
        format!("extract · {} findings from transcript", findings.len()),
    );
    let persisted = persist_uaf_hunt_findings(&run.target, &findings, &outcome.transcript, ctx)?;
    emit_uaf_hunt_done(ctx, findings.len());

    Ok(UafHuntReport {
        target: run.target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        compile_commands_path: run.options.compile_commands_path.display().to_string(),
        clang_tool_calls: stats.calls,
        first_clang_error: stats.first_error,
        steps_used: outcome.steps_used,
        truncated: outcome.truncated,
        cost_usd: outcome.cost_usd,
    })
}

fn emit_uaf_hunt_start(ctx: &ToolExecutionContext<'_>, target: &Path) -> Option<usize> {
    ctx.trace.map(|trace| {
        trace
            .step(
                "tool",
                "hunt",
                format!("uaf-hunt:hunt start · target={}", target.display()),
            )
            .emit()
    })
}

fn emit_uaf_hunt_progress(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    label: impl Into<String>,
) {
    emit_uaf_hunt_child(ctx, parent_step, "tool-progress", label);
}

fn emit_uaf_hunt_child(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    kind: &str,
    label: impl Into<String>,
) {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return;
    };
    let _ = trace.child(parent).step(kind, "hunt", label.into()).emit();
}

fn begin_uaf_hunt_agent_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
) -> Option<crate::run_artifacts::ParentScope> {
    let (Some(trace), Some(parent)) = (ctx.trace, parent_step) else {
        return None;
    };
    let phase = trace
        .child(parent)
        .step("reasoning", "hunt", "agent-loop · clang-navigation")
        .emit();
    Some(trace.parent_scope(phase))
}

fn emit_uaf_hunt_done(ctx: &ToolExecutionContext<'_>, finding_count: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "hunt",
                format!("uaf-hunt:hunt complete · {finding_count} findings"),
            )
            .emit();
    }
}

fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let resolved = match requested_uaf_target(input)? {
        Some(target) => resolve_requested_uaf_target(target, ctx)?,
        None => context_uaf_target(ctx)?,
    };
    ensure_uaf_target_dir(&resolved)?;
    Ok(resolved)
}

fn requested_uaf_target(input: &Value) -> Result<Option<PathBuf>> {
    input
        .get("target")
        .and_then(Value::as_str)
        .map(normalize_requested_uaf_target)
        .transpose()
}

fn normalize_requested_uaf_target(raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!("uaf-hunt target may not be blank")
    }
    let candidate = PathBuf::from(trimmed);
    Ok(candidate)
}

fn resolve_requested_uaf_target(
    candidate: PathBuf,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if candidate.is_absolute() {
        return Ok(candidate);
    }
    Ok(required_uaf_workspace(ctx)?.join(candidate))
}

fn context_uaf_target(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    Ok(required_uaf_workspace(ctx)?.to_path_buf())
}

fn ensure_uaf_target_dir(resolved: &Path) -> Result<()> {
    if !resolved.is_dir() {
        anyhow::bail!(
            "uaf-hunt:hunt: target is not a directory: {}",
            resolved.display()
        );
    }
    Ok(())
}

fn required_uaf_workspace<'a>(ctx: &'a ToolExecutionContext<'_>) -> Result<&'a Path> {
    ctx.workspace
        .map(WorkspaceTarget::root)
        .context("uaf-hunt requires an explicit active workspace")
}

fn require_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.ok_or_else(|| {
        anyhow::anyhow!(crate::runtime::missing_agent_runtime_message(
            "uaf-hunt:hunt"
        ))
    })
}

fn build_loop_request(
    target: &Path,
    options: &UafHuntInput,
    ctx: &ToolExecutionContext<'_>,
) -> Result<AgentToolLoopRequest> {
    let model = crate::runtime::resolve_explicit_model(
        "uaf-hunt:hunt",
        options.model.clone(),
        ctx.config.model.as_deref(),
    )?;
    Ok(AgentToolLoopRequest {
        model,
        cwd: target.to_path_buf(),
        system_prompt: UAF_HUNT_SYSTEM_PROMPT.to_string(),
        prompt: build_uaf_hunt_user_prompt(options),
        tools: uaf_hunt_agent_tools(),
        max_steps: options.max_agent_steps,
        runtime_options: None,
        temperature: None,
    })
}
