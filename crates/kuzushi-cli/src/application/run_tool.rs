use crate::tool_requirements::{
    reject_shell_only_run_dot, run_tool_workspace, tool_needs_finding_store, tool_needs_runtime,
};
use crate::tool_run_artifacts::{fail_cli_tool_run, finish_cli_tool_run};
use anyhow::{Context, Result};
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::run_artifacts::{
    load_run_summary, output_with_run_fallback_context, record_tool_run_started, ToolRunRecord,
};
use kuzushi_core::{
    load_config_for_target, new_run_id, AgentRuntime, FindingStore, ModuleRegistry,
    ToolOptionStore, TraceHandle, WorkspaceTarget,
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
    fail_cli_on_failed_tool_output(&output)
}

struct PreparedCliToolRun {
    tool: String,
    workspace: Option<WorkspaceTarget>,
    config: kuzushi_core::V2Config,
    store: Option<FindingStore>,
    registry: ModuleRegistry,
    input: serde_json::Value,
    artifact_target: PathBuf,
    run_id: String,
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
    let (artifact_target, run_id) =
        start_cli_tool_run_artifacts(workspace.as_ref(), &tool, &input)?;
    Ok(PreparedCliToolRun {
        tool,
        workspace,
        config,
        store,
        registry,
        input,
        artifact_target,
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
) -> Result<(PathBuf, String)> {
    let target = cli_tool_run_artifact_target(workspace)?;
    let run_id = start_cli_tool_run(&target, tool, input);
    Ok((target, run_id))
}

fn execute_cli_tool_run(run: &PreparedCliToolRun) -> Result<serde_json::Value> {
    let runtime = cli_tool_runtime(run)?;
    let trace = cli_tool_trace(run);
    let runtime_ref = active_cli_tool_runtime(runtime.as_ref());
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
    Some(
        TraceHandle::jsonl(&run.artifact_target, &run.run_id)
            .for_tool(&run.tool)
            .child(1),
    )
}

fn active_cli_tool_runtime<'a>(
    runtime: Option<&'a PiAgentCoreRuntime>,
) -> Option<&'a dyn AgentRuntime> {
    runtime.map(|runtime| runtime as &dyn AgentRuntime)
}

fn handle_cli_tool_result(
    run: &PreparedCliToolRun,
    result: Result<serde_json::Value>,
) -> Result<serde_json::Value> {
    match result {
        Ok(output) => {
            finish_cli_tool_run_artifacts(run, &output);
            Ok(cli_output_with_fallback_context(run, output))
        }
        Err(error) => {
            let message = error.to_string();
            fail_cli_tool_run_artifacts(run, &message);
            Ok(cli_failed_output_with_fallback_context(run, &message))
        }
    }
}

fn cli_failed_output_with_fallback_context(
    run: &PreparedCliToolRun,
    error: &str,
) -> serde_json::Value {
    cli_output_with_fallback_context(run, cli_failed_tool_output(run, error))
}

fn cli_failed_tool_output(run: &PreparedCliToolRun, error: &str) -> serde_json::Value {
    serde_json::json!({
        "ok": false,
        "status": "failed",
        "summary": format!("{} failed", run.tool),
        "artifacts": cli_run_artifacts(run),
        "warnings": [],
        "errors": [error],
    })
}

fn cli_run_artifacts(run: &PreparedCliToolRun) -> serde_json::Value {
    load_run_summary(&run.artifact_target, &run.run_id)
        .ok()
        .and_then(|summary| serde_json::to_value(summary.artifacts).ok())
        .unwrap_or_else(|| serde_json::json!([]))
}

fn cli_output_with_fallback_context(
    run: &PreparedCliToolRun,
    output: serde_json::Value,
) -> serde_json::Value {
    output_with_run_fallback_context(&run.artifact_target, &run.run_id, output)
}

fn fail_cli_on_failed_tool_output(output: &serde_json::Value) -> Result<()> {
    if output.get("status").and_then(serde_json::Value::as_str) != Some("failed") {
        return Ok(());
    }
    anyhow::bail!("{}", cli_failed_tool_message(output));
}

fn cli_failed_tool_message(output: &serde_json::Value) -> String {
    output
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(serde_json::Value::as_str)
        .or_else(|| output.get("summary").and_then(serde_json::Value::as_str))
        .unwrap_or("tool returned status=failed")
        .to_string()
}

fn finish_cli_tool_run_artifacts(run: &PreparedCliToolRun, output: &serde_json::Value) {
    finish_cli_tool_run(&run.artifact_target, &run.run_id, &run.tool, output);
}

fn fail_cli_tool_run_artifacts(run: &PreparedCliToolRun, error: &str) {
    fail_cli_tool_run(&run.artifact_target, &run.run_id, &run.tool, error);
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

fn cli_tool_run_artifact_target(workspace: Option<&WorkspaceTarget>) -> Result<PathBuf> {
    match workspace {
        Some(workspace) => Ok(workspace.root().to_path_buf()),
        None => Ok(std::env::current_dir()?),
    }
}

pub(crate) fn start_cli_tool_run(target: &Path, tool: &str, input: &serde_json::Value) -> String {
    let run_id = new_run_id("run");
    let record = ToolRunRecord::new(target, &run_id, "run", tool);
    record_tool_run_started(record, input);
    run_id
}
