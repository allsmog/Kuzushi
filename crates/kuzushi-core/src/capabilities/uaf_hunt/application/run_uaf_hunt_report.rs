use crate::capabilities::uaf_hunt::adapters::clang_subprocess::ClangMcpClient;
use crate::capabilities::uaf_hunt::adapters::parse_uaf_hunt_input;
use crate::capabilities::uaf_hunt::application::{
    build_uaf_hunt_user_prompt, persist_uaf_hunt_findings, uaf_hunt_agent_tools,
    UAF_HUNT_SYSTEM_PROMPT,
};
use crate::capabilities::uaf_hunt::domain::{UafHuntInput, UafHuntReport};
use crate::modules::ToolExecutionContext;
use crate::runtime::{run_tool_loop, AgentRuntime, AgentToolLoopRequest};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};

use super::extract_findings::extract_findings;
use super::toolbox::{
    build_uaf_hunt_toolbox, new_clang_call_stats, snapshot_clang_call_stats,
};

pub fn run_uaf_hunt_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<UafHuntReport> {
    let target = resolve_target(input, ctx)?;
    let options = parse_uaf_hunt_input(input, &target)?;
    let runtime = require_runtime(runtime)?;
    if !runtime.supports_tools() {
        anyhow::bail!(
            "uaf-hunt:hunt: configured runtime does not support tool-augmented loops. \
             PiAgentCoreRuntime is required; check the bridge configuration."
        );
    }

    let request = build_loop_request(&target, &options, ctx)?;
    runtime
        .preflight_tool_loop_blocking(&request)
        .context("uaf-hunt: agent tool-loop preflight failed")?;

    let mut clang = ClangMcpClient::spawn(&target, &options.compile_commands_path)?;
    let clang_stats = new_clang_call_stats();
    let toolbox = build_uaf_hunt_toolbox(&target, &options, &mut clang, clang_stats.clone());
    let mut handler = toolbox;
    let outcome = run_tool_loop(runtime, &request, &mut handler)
        .context("uaf-hunt: agent tool-loop failed")?;

    let stats = snapshot_clang_call_stats(&clang_stats);
    let findings = extract_findings(&outcome, &options)?;
    let persisted = persist_uaf_hunt_findings(&target, &findings, &outcome.transcript, ctx)?;

    Ok(UafHuntReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        compile_commands_path: options.compile_commands_path.display().to_string(),
        clang_tool_calls: stats.calls,
        first_clang_error: stats.first_error,
        steps_used: outcome.steps_used,
        truncated: outcome.truncated,
        cost_usd: outcome.cost_usd,
    })
}

fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let resolved = match requested_uaf_target(input)? {
        Some(target) => target,
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
        return current_dir_target();
    }
    let candidate = PathBuf::from(trimmed);
    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        Ok(current_dir_target()?.join(candidate))
    }
}

fn context_uaf_target(ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    ctx.workspace
        .map(|workspace| Ok(workspace.root().to_path_buf()))
        .unwrap_or_else(current_dir_target)
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

fn current_dir_target() -> Result<PathBuf> {
    std::env::current_dir().context("uaf-hunt: could not resolve current directory")
}

fn require_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.ok_or_else(|| {
        anyhow::anyhow!(
            "uaf-hunt:hunt requires an agent runtime; none configured. \
             Set a model with `model anthropic:claude-haiku-4-5` (shell) \
             or `KUZUSHI_MODEL=...` (CLI) before invoking."
        )
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
