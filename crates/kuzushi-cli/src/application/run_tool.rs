#[cfg(test)]
pub(crate) use super::run_tool_prepare::start_cli_tool_run_with_loaded_modules;
use super::run_tool_prepare::{prepare_cli_tool_run, PreparedCliToolRun};
use crate::tool_requirements::resolve_run_target;
use crate::tool_run_artifacts::finish_cli_tool_run;
use anyhow::Result;
use kuzushi_core::run_artifacts::{
    load_run_artifacts, load_run_summary, output_with_run_fallback_context,
};
use kuzushi_core::{
    failed_tool_output, tool_result_status, AgentRuntime, ToolExecutionContext, ToolOptionStore,
    ToolResultStatus, TraceHandle, WorkspaceTarget,
};
use kuzushi_openai::LangGraphRuntime;
use std::path::{Path, PathBuf};

pub(crate) fn run_tool_command(
    tool: String,
    input: String,
    options: Vec<String>,
    autonomy: Option<String>,
    global_target: Option<PathBuf>,
    load: Vec<String>,
) -> Result<()> {
    let input = resolve_run_input(input)?;
    let target = resolve_run_target(global_target);
    let tool_label = tool.clone();
    match prepare_cli_tool_run(tool, input, options, autonomy, target, load) {
        Ok(run) => {
            let output = execute_cli_tool_run(&run)?;
            println!("{}", serde_json::to_string_pretty(&output)?);
            fail_cli_on_failure_like_tool_output(&output)
        }
        // Prepare-stage failures (unknown tool, bad JSON, unknown option, missing
        // workspace) must emit the same machine-readable envelope as execution
        // failures — a CI job piping stdout through `jq` should never hit empty
        // stdout just because the tool couldn't be prepared.
        Err(error) => {
            let message = error.to_string();
            let output = prepare_failure_output(&tool_label, &message);
            println!("{}", serde_json::to_string_pretty(&output)?);
            anyhow::bail!("{message}")
        }
    }
}

/// Resolve the `--input` value: `-` reads JSON from stdin, `@path` reads it
/// from a file, and anything else is treated as inline JSON. `@` and `-` are
/// never valid starts for a JSON document, so this sigil is unambiguous.
fn resolve_run_input(input: String) -> Result<String> {
    if input == "-" {
        return std::io::read_to_string(std::io::stdin())
            .map_err(|error| anyhow::anyhow!("--input - could not read stdin: {error}"));
    }
    if let Some(path) = input.strip_prefix('@') {
        return std::fs::read_to_string(path)
            .map_err(|error| anyhow::anyhow!("--input @{path} could not be read: {error}"));
    }
    Ok(input)
}

fn prepare_failure_output(tool: &str, error: &str) -> serde_json::Value {
    failed_tool_output(tool, error, serde_json::json!([]))
}

fn execute_cli_tool_run(run: &PreparedCliToolRun) -> Result<serde_json::Value> {
    let runtime = match cli_tool_runtime(run) {
        Ok(runtime) => runtime,
        Err(error) => {
            let message = error.to_string();
            let output = cli_failed_tool_output(run, &message);
            return Ok(cli_output_after_persistence(
                run,
                output,
                fail_cli_tool_run_artifacts(run, &message),
            ));
        }
    };
    let trace = cli_tool_trace(run);
    let runtime_ref = active_cli_tool_runtime(runtime.as_ref());
    let ctx = ToolExecutionContext {
        config: &run.config,
        workspace: run.workspace.as_ref(),
        findings_store: run.store.as_ref(),
        trace: trace.as_ref(),
        cancellation: None,
        authorization: Default::default(),
    };
    let result = run
        .registry
        .prepare_dispatch_input(&run.tool, run.input.clone(), &ctx, None)
        .map(authorize_explicit_cli_tool)
        .and_then(|prepared| {
            run.registry
                .dispatch_prepared_input_with_runtime(prepared, &ctx, runtime_ref)
        });
    handle_cli_tool_result(run, result)
}

fn authorize_explicit_cli_tool(
    prepared: kuzushi_core::PreparedToolInput,
) -> kuzushi_core::PreparedToolInput {
    let delegates_patch = prepared.tool_name() == "sast:scan"
        && prepared
            .value()
            .get("autoPatch")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    if delegates_patch {
        return prepared.authorize_explicit_headless_with_delegated_tools(&["patch:finding"]);
    }
    prepared.authorize_explicit_headless()
}

fn cli_tool_runtime(run: &PreparedCliToolRun) -> Result<Option<LangGraphRuntime>> {
    if run
        .registry
        .tool_wants_runtime(&run.tool, &run.input, &run.config)
    {
        return Ok(Some(LangGraphRuntime::from_config(
            &run.config,
            run.workspace
                .as_ref()
                .map(|workspace| workspace.root())
                .unwrap_or(&run.artifact_target)
                .to_path_buf(),
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
    runtime: Option<&'a LangGraphRuntime>,
) -> Option<&'a dyn AgentRuntime> {
    runtime.map(|runtime| runtime as &dyn AgentRuntime)
}

fn handle_cli_tool_result(
    run: &PreparedCliToolRun,
    result: Result<serde_json::Value>,
) -> Result<serde_json::Value> {
    match result {
        Ok(output) => {
            let persistence = finish_cli_tool_run_artifacts(run, &output);
            Ok(cli_output_after_persistence(run, output, persistence))
        }
        Err(error) => {
            let message = error.to_string();
            let output = cli_failed_tool_output(run, &message);
            Ok(cli_output_after_persistence(
                run,
                output,
                fail_cli_tool_run_artifacts(run, &message),
            ))
        }
    }
}

fn cli_output_after_persistence(
    run: &PreparedCliToolRun,
    output: serde_json::Value,
    persistence: Result<()>,
) -> serde_json::Value {
    match persistence {
        Ok(()) => cli_output_with_fallback_context(run, output),
        Err(error) => cli_persistence_failure_output(run, output, &error),
    }
}

fn cli_failed_tool_output(run: &PreparedCliToolRun, error: &str) -> serde_json::Value {
    failed_tool_output(&run.tool, error, cli_run_artifacts(run))
}

fn cli_persistence_failure_output(
    run: &PreparedCliToolRun,
    original_output: serde_json::Value,
    error: &anyhow::Error,
) -> serde_json::Value {
    let original_output = cli_output_with_fallback_context(run, original_output);
    let persistence_error = format!("run artifact persistence failed: {error}");
    let artifacts = original_output
        .get("artifacts")
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));
    let mut output = failed_tool_output(&run.tool, &persistence_error, artifacts);
    output["summary"] = serde_json::json!(format!("{} result could not be persisted", run.tool));
    output["errors"] = serde_json::json!(persistence_errors(&persistence_error, &original_output));
    output["data"] = serde_json::json!({
        "artifactPersistenceError": persistence_error,
        "originalResult": original_output,
    });
    output_with_run_fallback_context(&run.artifact_target, &run.run_id, output)
}

fn persistence_errors(persistence_error: &str, original_output: &serde_json::Value) -> Vec<String> {
    let mut errors = vec![persistence_error.to_string()];
    errors.extend(
        original_output
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .filter(|error| *error != persistence_error)
            .map(ToString::to_string),
    );
    errors
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
    let output = output_with_cli_run_artifacts(&run.artifact_target, &run.run_id, output);
    output_with_run_fallback_context(&run.artifact_target, &run.run_id, output)
}

pub(crate) fn output_with_cli_run_artifacts(
    target: &Path,
    run_id: &str,
    mut output: serde_json::Value,
) -> serde_json::Value {
    let Some(object) = output.as_object_mut() else {
        return output;
    };
    if output_has_artifacts(object) {
        return output;
    }
    if let Ok(artifacts) = load_run_artifacts(target, run_id) {
        object.insert("artifacts".to_string(), serde_json::json!(artifacts));
    }
    output
}

fn output_has_artifacts(object: &serde_json::Map<String, serde_json::Value>) -> bool {
    match object.get("artifacts") {
        Some(serde_json::Value::Array(items)) => !items.is_empty(),
        Some(serde_json::Value::Null) | None => false,
        Some(_) => true,
    }
}

fn fail_cli_on_failure_like_tool_output(output: &serde_json::Value) -> Result<()> {
    let status = tool_result_status(output);
    if status.is_failure_like() {
        anyhow::bail!("{}", cli_failure_like_tool_message(output, status));
    }
    Ok(())
}

fn cli_failure_like_tool_message(output: &serde_json::Value, status: ToolResultStatus) -> String {
    output
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(serde_json::Value::as_str)
        .or_else(|| output.get("summary").and_then(serde_json::Value::as_str))
        .unwrap_or(match status {
            ToolResultStatus::Partial => "tool returned status=partial",
            _ => "tool returned status=failed",
        })
        .to_string()
}

fn finish_cli_tool_run_artifacts(
    run: &PreparedCliToolRun,
    output: &serde_json::Value,
) -> Result<()> {
    finish_cli_tool_run(&run.artifact_target, &run.run_id, &run.tool, output)
}

fn fail_cli_tool_run_artifacts(run: &PreparedCliToolRun, error: &str) -> Result<()> {
    crate::tool_run_artifacts::try_fail_cli_tool_run(
        &run.artifact_target,
        &run.run_id,
        &run.tool,
        error,
    )
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

#[cfg(test)]
mod tests {
    use super::{
        fail_cli_on_failure_like_tool_output, handle_cli_tool_result, prepare_cli_tool_run,
    };
    use serde_json::json;

    #[test]
    fn cli_exit_semantics_follow_the_canonical_tool_result_status() {
        assert!(fail_cli_on_failure_like_tool_output(&json!({"status": "completed"})).is_ok());
        assert!(fail_cli_on_failure_like_tool_output(&json!({"status": "skipped"})).is_ok());
        assert!(fail_cli_on_failure_like_tool_output(&json!({"status": "partial"})).is_err());
        assert!(fail_cli_on_failure_like_tool_output(&json!({"ok": false})).is_err());
    }

    #[test]
    fn persistence_failure_becomes_a_machine_readable_failed_output() {
        let target = tempfile::tempdir().unwrap();
        let run = prepare_cli_tool_run(
            "workspace:status".to_string(),
            "{}".to_string(),
            Vec::new(),
            None,
            Some(target.path().to_path_buf()),
            Vec::new(),
        )
        .unwrap();
        let run_dir = kuzushi_core::run_dir(target.path(), &run.run_id);
        std::fs::remove_dir_all(&run_dir).unwrap();
        std::fs::write(&run_dir, "not a directory").unwrap();

        let output = handle_cli_tool_result(
            &run,
            Ok(json!({
                "ok": true,
                "status": "completed",
                "summary": "workspace ready",
                "artifacts": [],
            })),
        )
        .unwrap();

        assert_eq!(output["status"], "failed");
        assert_eq!(output["ok"], false);
        assert_eq!(output["data"]["originalResult"]["status"], "completed");
        assert!(output["data"]["artifactPersistenceError"]
            .as_str()
            .is_some_and(|error| error.contains("persistence failed")));
        assert!(fail_cli_on_failure_like_tool_output(&output).is_err());
    }
}
