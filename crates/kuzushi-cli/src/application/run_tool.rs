use crate::tool_requirements::{
    reject_shell_only_run_dot, run_tool_workspace, tool_needs_finding_store, tool_needs_runtime,
};
use crate::tool_run_artifacts::{fail_cli_tool_run, finish_cli_tool_run};
use anyhow::{Context, Result};
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    append_run_trace_step, load_config_for_target, new_run_id, write_run_artifact_json,
    write_run_summary, AgentRuntime, FindingStore, ModuleRegistry, RunSummary, RunTraceStep,
    ToolOptionStore, TraceHandle, TracedRuntime, WorkspaceTarget,
};
use kuzushi_openai::PiAgentCoreRuntime;
use std::path::{Path, PathBuf};

pub(crate) fn run_tool_command(
    tool: String,
    input: String,
    options: Vec<String>,
    target: Option<PathBuf>,
) -> Result<()> {
    reject_shell_only_run_dot(&tool)?;
    let workspace = run_tool_workspace(&tool, target.as_deref())?;
    let config = load_config_for_target(workspace.as_ref().map(WorkspaceTarget::root))?;
    let store = workspace
        .as_ref()
        .filter(|_| tool_needs_finding_store(&tool))
        .map(|workspace| FindingStore::open(workspace.findings_db_path()))
        .transpose()?;
    let registry = ModuleRegistry::with_v2_builtins();
    let input = serde_json::from_str(&input).context("--input must be JSON")?;
    let option_store = run_option_store(workspace.as_ref(), &tool, &options)?;
    let input = registry.prepare_tool_input(&tool, input, Some(&option_store))?;
    let run_id = workspace
        .as_ref()
        .map(|workspace| start_cli_tool_run(workspace.root(), &tool, &input));
    let runtime = if tool_needs_runtime(&tool, &input) {
        Some(PiAgentCoreRuntime::from_config(
            &config,
            std::env::current_dir()?,
        )?)
    } else {
        None
    };
    let trace = workspace
        .as_ref()
        .zip(run_id.as_ref())
        .map(|(workspace, run_id)| {
            TraceHandle::jsonl(workspace.root(), run_id)
                .for_tool(&tool)
                .child(1)
        });
    let traced_runtime = runtime
        .as_ref()
        .zip(trace.as_ref())
        .map(|(runtime, trace)| TracedRuntime::new(runtime as &dyn AgentRuntime, trace.clone()));
    let runtime_ref = traced_runtime
        .as_ref()
        .map(|runtime| runtime as &dyn AgentRuntime)
        .or_else(|| runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime));
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: workspace.as_ref(),
        findings_store: store.as_ref(),
        trace: trace.as_ref(),
    };
    let result = registry.execute_tool_with_runtime(&tool, input, &ctx, runtime_ref);
    let output = match result {
        Ok(output) => {
            if let (Some(workspace), Some(run_id)) = (workspace.as_ref(), run_id.as_deref()) {
                finish_cli_tool_run(workspace.root(), run_id, &tool, &output);
            }
            output
        }
        Err(error) => {
            if let (Some(workspace), Some(run_id)) = (workspace.as_ref(), run_id.as_deref()) {
                fail_cli_tool_run(workspace.root(), run_id, &tool, &error.to_string());
            }
            return Err(error);
        }
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

pub(crate) fn run_option_store(
    workspace: Option<&WorkspaceTarget>,
    tool: &str,
    options: &[String],
) -> Result<ToolOptionStore> {
    let paths = kuzushi_core::ConfigPaths::from_target(workspace.map(WorkspaceTarget::root))?;
    let mut store = ToolOptionStore::load_persistent(
        &paths.global_options_path(),
        paths.project_options_path().as_deref(),
    )?;
    for option in options {
        apply_option_override(&mut store, tool, option)?;
    }
    Ok(store)
}

pub(crate) fn apply_option_override(
    store: &mut ToolOptionStore,
    tool: &str,
    option: &str,
) -> Result<()> {
    let (name, value) = parse_option_override(option)?;
    store.set_value(
        kuzushi_core::OptionScope::Session,
        kuzushi_core::OptionTarget::Tool(tool.to_string()),
        name,
        serde_json::Value::String(value),
    );
    Ok(())
}

pub(crate) fn parse_option_override(raw: &str) -> Result<(String, String)> {
    let Some((name, value)) = raw.split_once('=') else {
        anyhow::bail!("--option must be key=value, got {raw:?}");
    };
    let name = name.trim();
    if name.is_empty() {
        anyhow::bail!("--option key must not be empty");
    }
    Ok((name.to_string(), value.trim().to_string()))
}

pub(crate) fn start_cli_tool_run(target: &Path, tool: &str, input: &serde_json::Value) -> String {
    let run_id = new_run_id("run");
    let input_artifact =
        write_run_artifact_json(target, &run_id, "input.json", "input", input).ok();
    let mut summary = RunSummary::running(
        run_id.clone(),
        "run",
        Some(tool.to_string()),
        target.display().to_string(),
    );
    if let Some(artifact) = input_artifact {
        summary = summary.with_artifact(artifact);
    }
    let _ = append_run_trace_step(
        target,
        &run_id,
        &RunTraceStep::new(1, "tool", format!("{tool} started")).with_tool_name(tool),
    );
    let _ = write_run_summary(target, &summary);
    run_id
}
