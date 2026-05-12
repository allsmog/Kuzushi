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
    let run = prepare_cli_tool_run(tool, input, options, target)?;
    let output = execute_cli_tool_run(&run)?;
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

struct PreparedCliToolRun {
    tool: String,
    workspace: Option<WorkspaceTarget>,
    config: kuzushi_core::V2Config,
    store: Option<FindingStore>,
    registry: ModuleRegistry,
    input: serde_json::Value,
    run_id: Option<String>,
}

fn prepare_cli_tool_run(
    tool: String,
    input: String,
    options: Vec<String>,
    target: Option<PathBuf>,
) -> Result<PreparedCliToolRun> {
    reject_shell_only_run_dot(&tool)?;
    let workspace = run_tool_workspace(&tool, target.as_deref())?;
    let config = load_config_for_target(workspace.as_ref().map(WorkspaceTarget::root))?;
    let registry = ModuleRegistry::with_v2_builtins();
    let input = serde_json::from_str(&input).context("--input must be JSON")?;
    let option_store = run_option_store(workspace.as_ref(), &tool, &options)?;
    let input = registry.prepare_tool_input(&tool, input, Some(&option_store))?;
    let store = open_cli_tool_finding_store(workspace.as_ref(), &tool)?;
    let run_id = start_cli_tool_run_artifacts(workspace.as_ref(), &tool, &input);
    Ok(PreparedCliToolRun {
        tool,
        workspace,
        config,
        store,
        registry,
        input,
        run_id,
    })
}

fn open_cli_tool_finding_store(
    workspace: Option<&WorkspaceTarget>,
    tool: &str,
) -> Result<Option<FindingStore>> {
    workspace
        .filter(|_| tool_needs_finding_store(tool))
        .map(|workspace| FindingStore::open(workspace.findings_db_path()))
        .transpose()
}

fn start_cli_tool_run_artifacts(
    workspace: Option<&WorkspaceTarget>,
    tool: &str,
    input: &serde_json::Value,
) -> Option<String> {
    workspace.map(|workspace| start_cli_tool_run(workspace.root(), tool, input))
}

fn execute_cli_tool_run(run: &PreparedCliToolRun) -> Result<serde_json::Value> {
    let runtime = cli_tool_runtime(run)?;
    let trace = cli_tool_trace(run);
    let traced_runtime = traced_cli_tool_runtime(runtime.as_ref(), trace.as_ref());
    let runtime_ref = active_cli_tool_runtime(runtime.as_ref(), traced_runtime.as_ref());
    let ctx = ToolExecutionContext {
        config: &run.config,
        workspace: run.workspace.as_ref(),
        findings_store: run.store.as_ref(),
        trace: trace.as_ref(),
    };
    let result =
        run.registry
            .execute_tool_with_runtime(&run.tool, run.input.clone(), &ctx, runtime_ref);
    handle_cli_tool_result(run, result)
}

fn cli_tool_runtime(run: &PreparedCliToolRun) -> Result<Option<PiAgentCoreRuntime>> {
    if tool_needs_runtime(&run.tool, &run.input) {
        return Ok(Some(PiAgentCoreRuntime::from_config(
            &run.config,
            std::env::current_dir()?,
        )?));
    }
    Ok(None)
}

fn cli_tool_trace(run: &PreparedCliToolRun) -> Option<TraceHandle> {
    run.workspace
        .as_ref()
        .zip(run.run_id.as_ref())
        .map(|(workspace, run_id)| {
            TraceHandle::jsonl(workspace.root(), run_id)
                .for_tool(&run.tool)
                .child(1)
        })
}

fn traced_cli_tool_runtime<'a>(
    runtime: Option<&'a PiAgentCoreRuntime>,
    trace: Option<&'a TraceHandle>,
) -> Option<TracedRuntime<'a>> {
    runtime
        .zip(trace)
        .map(|(runtime, trace)| TracedRuntime::new(runtime as &dyn AgentRuntime, trace.clone()))
}

fn active_cli_tool_runtime<'a>(
    runtime: Option<&'a PiAgentCoreRuntime>,
    traced_runtime: Option<&'a TracedRuntime<'a>>,
) -> Option<&'a dyn AgentRuntime> {
    traced_runtime
        .map(|runtime| runtime as &dyn AgentRuntime)
        .or_else(|| runtime.map(|runtime| runtime as &dyn AgentRuntime))
}

fn handle_cli_tool_result(
    run: &PreparedCliToolRun,
    result: Result<serde_json::Value>,
) -> Result<serde_json::Value> {
    match result {
        Ok(output) => {
            finish_cli_tool_run_artifacts(run, &output);
            Ok(output)
        }
        Err(error) => {
            fail_cli_tool_run_artifacts(run, &error.to_string());
            Err(error)
        }
    }
}

fn finish_cli_tool_run_artifacts(run: &PreparedCliToolRun, output: &serde_json::Value) {
    if let (Some(workspace), Some(run_id)) = (run.workspace.as_ref(), run.run_id.as_deref()) {
        finish_cli_tool_run(workspace.root(), run_id, &run.tool, output);
    }
}

fn fail_cli_tool_run_artifacts(run: &PreparedCliToolRun, error: &str) {
    if let (Some(workspace), Some(run_id)) = (run.workspace.as_ref(), run.run_id.as_deref()) {
        fail_cli_tool_run(workspace.root(), run_id, &run.tool, error);
    }
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
