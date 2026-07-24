use super::scan_gate::{apply_scan_gate_policy, ScanGatePolicy};
use super::scan_prepare::{
    prepare_scan_command, prepare_scan_command_with_requested_input, PreparedScanCommand, SCAN_TOOL,
};
use crate::command::ScanModeArg;
use crate::presentation::{emit_scan_ci_start, emit_scan_output, scan_result_or_report_ci_error};
use anyhow::{Context, Result};
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::run_artifacts::{
    try_record_tool_run_complete_settled, try_record_tool_run_failed_settled,
    try_record_tool_run_started_with_reproducibility, ToolRunRecord,
};
use kuzushi_core::run_lifecycle::{RunItemStatus, RunObservationHandle};
use kuzushi_core::{
    config_hash, new_run_id, tool_wants_runtime, AgentRuntime, FindingStore, ModuleRegistry,
    PreparedToolInput, ToolOptionStore, ToolResultStatus, TraceHandle, WorkspaceTarget,
};
use kuzushi_openai::LangGraphRuntime;
use std::path::{Path, PathBuf};

/// CLI scope flags (`--shard`, `--shard-manifest`, `--paths`) that compile
/// into the canonical `sast:scan` `paths`/`shard` input keys.
#[derive(Debug, Default)]
pub(crate) struct ScanScopeArgs {
    pub(crate) shard: Option<String>,
    pub(crate) shard_manifest: Option<PathBuf>,
    pub(crate) paths: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn scan_command(
    target: PathBuf,
    mode: Option<ScanModeArg>,
    tasks: Vec<String>,
    triage: Option<bool>,
    json: bool,
    ci: bool,
    budget: Option<String>,
    scope: ScanScopeArgs,
    since: Option<String>,
    include_worktree: bool,
    gate: ScanGatePolicy,
) -> Result<()> {
    if is_apk_file(&target) {
        return scan_apk_command(target, json, ci, gate).await;
    }
    execute_prepared_scan(
        prepare_scan_command(
            &target,
            mode,
            &tasks,
            triage,
            budget.as_deref(),
            &scope,
            since.as_deref(),
            include_worktree,
            json,
            ci,
        )?,
        &target,
        &tasks,
        json,
        ci,
        gate,
    )
}

pub(crate) async fn scan_command_with_requested_input(
    target: PathBuf,
    input: serde_json::Value,
    task_labels: Vec<String>,
    json: bool,
    ci: bool,
    gate: ScanGatePolicy,
) -> Result<()> {
    execute_prepared_scan(
        prepare_scan_command_with_requested_input(&target, input, json, ci)?,
        &target,
        &task_labels,
        json,
        ci,
        gate,
    )
}

fn execute_prepared_scan(
    prepared: PreparedScanCommand,
    target: &PathBuf,
    tasks: &[String],
    json: bool,
    ci: bool,
    gate: ScanGatePolicy,
) -> Result<()> {
    ScanInvocation {
        target,
        tasks,
        json,
        ci,
        gate,
    }
    .execute(prepared)
}

struct ScanInvocation<'a> {
    target: &'a Path,
    tasks: &'a [String],
    json: bool,
    ci: bool,
    gate: ScanGatePolicy,
}

impl ScanInvocation<'_> {
    fn execute(self, prepared: PreparedScanCommand) -> Result<()> {
        let PreparedScanCommand {
            workspace,
            config,
            store,
            registry,
            input,
            runtime,
            run_id,
        } = prepared;
        let (started, result) = begin_and_dispatch_prepared_scan(
            &self,
            &workspace,
            &store,
            &registry,
            &config,
            input,
            runtime.as_ref(),
            &run_id,
        )?;
        finish_scan_execution(
            ScanFinish {
                workspace: &workspace,
                store: &store,
                fallback_run_id: &run_id,
                json: self.json,
                ci: self.ci,
                started,
                gate: &self.gate,
            },
            result,
        )
    }
}

fn begin_and_dispatch_prepared_scan(
    invocation: &ScanInvocation<'_>,
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    registry: &ModuleRegistry,
    config: &kuzushi_core::V2Config,
    input: serde_json::Value,
    runtime: Option<&LangGraphRuntime>,
    run_id: &str,
) -> Result<(std::time::Instant, Result<serde_json::Value>)> {
    let started = begin_prepared_scan(
        workspace,
        store,
        registry,
        run_id,
        &input,
        config,
        invocation.target,
        invocation.tasks,
        invocation.ci,
    )?;
    let result = dispatch_prepared_scan(workspace, store, registry, config, input, runtime, run_id);
    Ok((started, result))
}

fn begin_prepared_scan(
    workspace: &WorkspaceTarget,
    _store: &FindingStore,
    registry: &ModuleRegistry,
    run_id: &str,
    input: &serde_json::Value,
    config: &kuzushi_core::V2Config,
    target: &Path,
    tasks: &[String],
    ci: bool,
) -> Result<std::time::Instant> {
    let started = std::time::Instant::now();
    emit_scan_ci_start(ci, started, target, config, tasks);
    record_scan_execution_started(workspace, registry, run_id, input, config)?;
    Ok(started)
}

fn dispatch_prepared_scan(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    registry: &ModuleRegistry,
    config: &kuzushi_core::V2Config,
    input: serde_json::Value,
    runtime: Option<&LangGraphRuntime>,
    run_id: &str,
) -> Result<serde_json::Value> {
    let trace = scan_trace(workspace, run_id)?;
    let ctx = ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    execute_scan_tool(ScanToolExecution {
        registry,
        input,
        ctx: &ctx,
        runtime,
        workspace,
        run_id,
        config,
    })
}

struct ScanFinish<'a> {
    workspace: &'a WorkspaceTarget,
    store: &'a FindingStore,
    fallback_run_id: &'a str,
    json: bool,
    ci: bool,
    started: std::time::Instant,
    gate: &'a ScanGatePolicy,
}

fn finish_scan_execution(finish: ScanFinish<'_>, result: Result<serde_json::Value>) -> Result<()> {
    let elapsed = finish.started.elapsed();
    let result = scan_result_or_report_ci_error(
        result,
        finish.workspace,
        finish.fallback_run_id,
        finish.ci,
        finish.started,
        elapsed,
    )?;
    let run_ids = scan_gate_ids(&result, finish.fallback_run_id);
    match scan_semantic_error(&result) {
        Some(error) => finish_semantic_scan_failure(finish, result, run_ids, error, elapsed),
        None => finish_completed_scan(finish, result, run_ids, elapsed),
    }
}

fn finish_completed_scan(
    finish: ScanFinish<'_>,
    result: serde_json::Value,
    run_ids: Vec<String>,
    elapsed: std::time::Duration,
) -> Result<()> {
    emit_scan_output(
        finish.workspace,
        &result,
        finish.json,
        finish.ci,
        finish.started,
        elapsed,
    )?;
    apply_scan_gate_policy(
        finish.workspace,
        finish.store,
        &run_ids,
        finish.fallback_run_id,
        finish.gate,
    )
}

fn finish_semantic_scan_failure(
    finish: ScanFinish<'_>,
    result: serde_json::Value,
    run_ids: Vec<String>,
    error: anyhow::Error,
    elapsed: std::time::Duration,
) -> Result<()> {
    let error = crate::presentation::scan_error_with_recovery(
        error,
        finish.workspace,
        finish.fallback_run_id,
    );
    if finish.ci {
        crate::presentation::emit_scan_ci_error(true, finish.started, elapsed, &error);
    } else {
        emit_scan_output(
            finish.workspace,
            &result,
            finish.json,
            false,
            finish.started,
            elapsed,
        )?;
    }
    apply_scan_gate_policy(
        finish.workspace,
        finish.store,
        &run_ids,
        finish.fallback_run_id,
        &ScanGatePolicy {
            fail_on: None,
            sarif: finish.gate.sarif.clone(),
        },
    )?;
    Err(error)
}

fn scan_semantic_error(result: &serde_json::Value) -> Option<anyhow::Error> {
    let status = kuzushi_core::tool_result_status(result);
    if !matches!(status, ToolResultStatus::Partial | ToolResultStatus::Failed) {
        return None;
    }
    let message = result
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(serde_json::Value::as_str)
        .or_else(|| result.get("summary").and_then(serde_json::Value::as_str))
        .unwrap_or(match status {
            ToolResultStatus::Partial => "scan returned status=partial",
            _ => "scan returned status=failed",
        });
    Some(anyhow::anyhow!(message.to_string()))
}

fn scan_trace(workspace: &WorkspaceTarget, run_id: &str) -> Result<TraceHandle> {
    Ok(
        kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(workspace.root(), run_id)?
            .start_root_task("Run the accepted Scan plan")?
            .trace_handle(),
    )
}

/// Reconcile suppression rules against the current clock before the scan so a
/// workspace with lapsed suppressions begins by reopening them. A failure here
/// is a hard error: the `--fail-on` gate must never honor a suppression that
/// could not be re-evaluated, so we refuse to run the scan on stale state
/// rather than silently passing a lapsed suppression.
fn scan_gate_ids(result: &serde_json::Value, fallback: &str) -> Vec<String> {
    let mut run_ids = std::collections::BTreeSet::new();
    insert_run_id(&mut run_ids, fallback);
    if let Some(run_id) = result
        .pointer("/data/runId")
        .and_then(serde_json::Value::as_str)
    {
        insert_run_id(&mut run_ids, run_id);
    }
    if let Some(children) = result.pointer("/data/runIds") {
        collect_run_ids(children, &mut run_ids);
    }
    run_ids.into_iter().collect()
}

fn collect_run_ids(value: &serde_json::Value, run_ids: &mut std::collections::BTreeSet<String>) {
    match value {
        serde_json::Value::String(run_id) => insert_run_id(run_ids, run_id),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_run_ids(value, run_ids);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                collect_run_ids(value, run_ids);
            }
        }
        _ => {}
    }
}

fn insert_run_id(run_ids: &mut std::collections::BTreeSet<String>, run_id: &str) {
    let run_id = run_id.trim();
    if !run_id.is_empty() {
        run_ids.insert(run_id.to_string());
    }
}

fn record_scan_execution_started(
    workspace: &WorkspaceTarget,
    registry: &ModuleRegistry,
    run_id: &str,
    input: &serde_json::Value,
    config: &kuzushi_core::V2Config,
) -> Result<()> {
    try_record_tool_run_started_with_reproducibility(
        ToolRunRecord::new(workspace.root(), run_id, "scan", SCAN_TOOL),
        input,
        kuzushi_core::tool_execution_model(SCAN_TOOL, input, config),
        config_hash(config).ok(),
        registry.loaded_module_specifiers(),
    )
}

struct ScanToolExecution<'a> {
    registry: &'a ModuleRegistry,
    input: serde_json::Value,
    ctx: &'a ToolExecutionContext<'a>,
    runtime: Option<&'a LangGraphRuntime>,
    workspace: &'a WorkspaceTarget,
    run_id: &'a str,
    config: &'a kuzushi_core::V2Config,
}

fn execute_scan_tool(execution: ScanToolExecution<'_>) -> Result<serde_json::Value> {
    let failure_input = execution.input.clone();
    let runtime = execution
        .runtime
        .map(|runtime| runtime as &dyn AgentRuntime);
    let prepared = execution
        .registry
        .prepare_dispatch_input(SCAN_TOOL, execution.input.clone(), execution.ctx, None)
        .map_err(|error| recorded_pre_execution_scan_error(&execution, &failure_input, error))?;
    emit_scan_patch_validation_disclosure(execution.workspace, prepared.value())
        .map_err(|error| recorded_pre_execution_scan_error(&execution, &failure_input, error))?;
    let observation = execution
        .ctx
        .run_observation()
        .context("scan dispatch lacks its semantic observation")?;
    observation
        .task_handle()
        .context("scan dispatch lacks its semantic task")?
        .update_and_flush(kuzushi_core::run_lifecycle::RunItemStatus::Running, None)?;
    let dispatched = execution
        .registry
        .dispatch_prepared_input_observed_with_runtime(
            authorize_headless_scan(prepared),
            execution.ctx,
            runtime,
        );
    let outcome = match dispatched {
        Ok(outcome) => outcome,
        Err(dispatch_error) => {
            return Err(recorded_pre_execution_scan_error(
                &execution,
                &failure_input,
                dispatch_error,
            ));
        }
    };
    settle_scan_dispatch(execution.workspace, execution.run_id, &observation, outcome)
}

fn settle_scan_dispatch(
    workspace: &WorkspaceTarget,
    run_id: &str,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    outcome: kuzushi_core::ObservedDispatchOutcome,
) -> Result<serde_json::Value> {
    let record = ToolRunRecord::new(workspace.root(), run_id, "scan", SCAN_TOOL);
    match outcome.execution {
        Ok(output) => {
            try_record_tool_run_complete_settled(record, &output, observation, outcome.completion)?;
            Ok(output)
        }
        Err(error) => match try_record_tool_run_failed_settled(
            record,
            &error.to_string(),
            observation,
            outcome.completion,
        ) {
            Ok(()) => Err(error),
            Err(persistence) => Err(error.context(format!(
                "also could not settle the failed scan lifecycle: {persistence:#}"
            ))),
        },
    }
}

fn recorded_pre_execution_scan_error(
    execution: &ScanToolExecution<'_>,
    failure_input: &serde_json::Value,
    error: anyhow::Error,
) -> anyhow::Error {
    let persistence = record_failed_scan_execution(
        ScanExecutionFailureRecord {
            workspace: execution.workspace,
            registry: execution.registry,
            run_id: execution.run_id,
            input: failure_input,
            config: execution.config,
            observation: execution.ctx.run_observation(),
        },
        &error,
    );
    match persistence {
        Ok(()) => error,
        Err(persistence) => error.context(format!(
            "also could not persist the pre-execution scan failure: {persistence:#}"
        )),
    }
}

fn emit_scan_patch_validation_disclosure(
    workspace: &WorkspaceTarget,
    input: &serde_json::Value,
) -> Result<()> {
    if !input
        .get("autoPatch")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(());
    }
    let disclosure = kuzushi_core::patch::patch_validation_disclosure(workspace.root(), input)?;
    eprintln!("kuzushi: approved auto-patch repository execution — {disclosure}");
    Ok(())
}

fn authorize_headless_scan(prepared: PreparedToolInput) -> PreparedToolInput {
    if prepared
        .value()
        .get("autoPatch")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return prepared.authorize_explicit_headless_with_delegated_tools(&["patch:finding"]);
    }
    prepared.authorize_explicit_headless()
}

struct ScanExecutionFailureRecord<'a> {
    workspace: &'a WorkspaceTarget,
    registry: &'a ModuleRegistry,
    run_id: &'a str,
    input: &'a serde_json::Value,
    config: &'a kuzushi_core::V2Config,
    observation: Option<RunObservationHandle>,
}

fn record_failed_scan_execution(
    record: ScanExecutionFailureRecord<'_>,
    error: &anyhow::Error,
) -> Result<()> {
    let tool_run = ToolRunRecord::new(record.workspace.root(), record.run_id, "scan", SCAN_TOOL);
    if kuzushi_core::load_run_summary(record.workspace.root(), record.run_id)
        .is_ok_and(|summary| summary.status != "running")
    {
        return Ok(());
    }
    if kuzushi_core::load_run_summary(record.workspace.root(), record.run_id).is_err() {
        try_record_tool_run_started_with_reproducibility(
            tool_run,
            record.input,
            kuzushi_core::tool_execution_model(SCAN_TOOL, record.input, record.config),
            config_hash(record.config).ok(),
            record.registry.loaded_module_specifiers(),
        )?;
    }
    let observation = record.observation.map_or_else(
        || RunObservationHandle::jsonl(record.workspace.root(), record.run_id),
        Ok,
    )?;
    let rejection = kuzushi_core::run_lifecycle::observe_preparation_rejection(
        &observation,
        SCAN_TOOL,
        record.input,
        "pre_execution_policy",
        &error.to_string(),
    )?;
    let (observation, completion) = rejection.into_parts();
    try_record_tool_run_failed_settled(tool_run, &error.to_string(), &observation, completion)
}

pub(crate) fn apply_scan_since_scope(
    workspace: &WorkspaceTarget,
    since: Option<&str>,
    include_worktree: bool,
    json: bool,
    ci: bool,
) -> Result<()> {
    let Some(since_ref) = since else {
        return Ok(());
    };
    let scope = kuzushi_core::git_diff_files(workspace.root(), since_ref, include_worktree)
        .with_context(|| format!("--since {since_ref:?} failed"))?;
    write_scan_scope_file(workspace, &scope.files)?;
    emit_scan_scope_line(&scope.files, since_ref, include_worktree, json, ci);
    Ok(())
}

fn write_scan_scope_file(workspace: &WorkspaceTarget, files: &[PathBuf]) -> Result<()> {
    let scope_file = workspace.findings_db_path().with_file_name("since.txt");
    let relative = scope_file
        .strip_prefix(workspace.root())
        .with_context(|| format!("{} escaped the workspace", scope_file.display()))?;
    kuzushi_core::workspace::write_workspace_state_file(
        workspace.root(),
        relative,
        scan_scope_body(files).as_bytes(),
    )?;
    Ok(())
}

pub(crate) fn scan_scope_body(files: &[PathBuf]) -> String {
    files
        .iter()
        .filter_map(|p| {
            let rendered = p.display().to_string();
            // A path containing `\n` or `\r` would inject extra entries in
            // the scope file consumed by downstream engines (since.txt is
            // line-delimited). Git accepts such paths in working-tree
            // entries, so a hostile target repo could craft one to bypass
            // scope. Drop instead of escape — legitimate filenames have
            // no embedded newlines.
            if rendered.contains('\n') || rendered.contains('\r') {
                eprintln!(
                    "scan-scope: dropping path with embedded newline/CR: {:?}",
                    rendered
                );
                return None;
            }
            Some(format!("{rendered}\n"))
        })
        .collect()
}

pub(crate) fn emit_scan_scope_line(
    files: &[PathBuf],
    since_ref: &str,
    include_worktree: bool,
    json: bool,
    ci: bool,
) {
    if !json && !ci {
        eprintln!(
            "scope: {} files since {} {}",
            files.len(),
            since_ref,
            scan_worktree_suffix(include_worktree)
        );
    }
}

pub(crate) fn scan_worktree_suffix(include_worktree: bool) -> &'static str {
    if include_worktree {
        "(+worktree)"
    } else {
        ""
    }
}

fn is_apk_file(target: &Path) -> bool {
    if !target.is_file() {
        return false;
    }
    target
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("apk"))
        .unwrap_or(false)
}

async fn scan_apk_command(apk: PathBuf, json: bool, ci: bool, gate: ScanGatePolicy) -> Result<()> {
    let workspace_dir = apk_workspace_dir(&apk)?;
    let workspace = WorkspaceTarget::new(&workspace_dir)?;
    let config = super::config_diagnostics::load_cli_config(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let registry = ModuleRegistry::with_v2_builtins();
    let run_id = new_run_id("scan");
    let observation = start_apk_scan_observation(&workspace, &run_id, &apk)?;
    let trace = observation.trace_handle();
    let input = prepare_apk_scan_input(
        &apk,
        &workspace_dir,
        &workspace,
        &config,
        &store,
        &registry,
        &run_id,
        &trace,
    )?;
    let started = std::time::Instant::now();
    emit_scan_ci_start(ci, started, &apk, &config, &[]);
    let record = ToolRunRecord::new(workspace.root(), &run_id, "scan", "android-apk:scan");
    record_apk_scan_started(record, &input, &config, &registry)?;
    mark_apk_scan_running(&observation)?;
    let outcome = dispatch_apk_scan(&workspace, &store, &config, &registry, input, &trace)?;
    let result = settle_apk_scan(record, &observation, outcome);
    finish_scan_execution(
        ScanFinish {
            workspace: &workspace,
            store: &store,
            fallback_run_id: &run_id,
            json,
            ci,
            started,
            gate: &gate,
        },
        result,
    )
}

fn start_apk_scan_observation(
    workspace: &WorkspaceTarget,
    run_id: &str,
    apk: &Path,
) -> Result<RunObservationHandle> {
    RunObservationHandle::jsonl(workspace.root(), run_id)?
        .start_root_task(format!("Scan APK {}", apk.display()))
}

fn mark_apk_scan_running(observation: &RunObservationHandle) -> Result<()> {
    observation
        .task_handle()
        .context("APK scan lacks its semantic task")?
        .update_and_flush(RunItemStatus::Running, None)?;
    Ok(())
}

fn apk_workspace_dir(apk: &Path) -> Result<PathBuf> {
    let canonical = apk
        .canonicalize()
        .with_context(|| format!("Could not resolve APK target {}", apk.display()))?;
    canonical
        .parent()
        .map(Path::to_path_buf)
        .context("APK target has no parent workspace")
}

fn prepare_apk_scan_input(
    apk: &Path,
    workspace_dir: &Path,
    workspace: &WorkspaceTarget,
    config: &kuzushi_core::V2Config,
    store: &FindingStore,
    registry: &ModuleRegistry,
    run_id: &str,
    trace: &TraceHandle,
) -> Result<serde_json::Value> {
    let ctx = scan_tool_context(workspace, config, store, trace);
    registry.prepare_tool_input_for_dispatch(
        "android-apk:scan",
        apk_scan_tool_input(apk, workspace_dir, run_id),
        &ctx,
        None,
    )
}

fn dispatch_apk_scan(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    config: &kuzushi_core::V2Config,
    registry: &ModuleRegistry,
    input: serde_json::Value,
    trace: &TraceHandle,
) -> Result<kuzushi_core::ObservedDispatchOutcome> {
    let ctx = scan_tool_context(workspace, config, store, trace);
    let prepared = registry
        .prepare_dispatch_input("android-apk:scan", input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_observed_with_runtime(prepared, &ctx, None)
}

fn scan_tool_context<'a>(
    workspace: &'a WorkspaceTarget,
    config: &'a kuzushi_core::V2Config,
    store: &'a FindingStore,
    trace: &'a TraceHandle,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: Some(trace),
        cancellation: None,
        authorization: Default::default(),
    }
}

fn record_apk_scan_started(
    record: ToolRunRecord<'_>,
    input: &serde_json::Value,
    config: &kuzushi_core::V2Config,
    registry: &ModuleRegistry,
) -> Result<()> {
    try_record_tool_run_started_with_reproducibility(
        record,
        input,
        kuzushi_core::tool_execution_model("android-apk:scan", input, config),
        config_hash(config).ok(),
        registry.loaded_module_specifiers(),
    )
}

fn settle_apk_scan(
    record: ToolRunRecord<'_>,
    observation: &RunObservationHandle,
    outcome: kuzushi_core::ObservedDispatchOutcome,
) -> Result<serde_json::Value> {
    match outcome.execution {
        Ok(output) => {
            try_record_tool_run_complete_settled(record, &output, observation, outcome.completion)?;
            Ok(output)
        }
        Err(error) => match try_record_tool_run_failed_settled(
            record,
            &error.to_string(),
            observation,
            outcome.completion,
        ) {
            Ok(()) => Err(error),
            Err(persistence) => Err(error.context(format!(
                "also could not settle the failed APK scan lifecycle: {persistence:#}"
            ))),
        },
    }
}

fn apk_scan_tool_input(apk: &Path, workspace: &Path, run_id: &str) -> serde_json::Value {
    serde_json::json!({
        "apk": apk.display().to_string(),
        "target": workspace.display().to_string(),
        "decompiler": "both",
        "runId": run_id,
    })
}

pub(crate) fn scan_tool_input(
    mode: Option<ScanModeArg>,
    tasks: &[String],
    triage: Option<bool>,
) -> serde_json::Value {
    let mut input = serde_json::Map::new();
    if let Some(mode) = mode {
        input.insert("mode".to_string(), serde_json::json!(mode.as_input_value()));
    }
    if !tasks.is_empty() {
        input.insert("taskMode".to_string(), serde_json::json!("manual"));
        input.insert("tasks".to_string(), serde_json::json!(tasks));
    }
    if let Some(triage) = triage {
        input.insert("triage".to_string(), serde_json::json!(triage));
    }
    serde_json::Value::Object(input)
}

pub(crate) fn scan_option_store(workspace: &WorkspaceTarget) -> Result<ToolOptionStore> {
    let paths = kuzushi_core::ConfigPaths::from_target(Some(workspace.root()))?;
    ToolOptionStore::load_persistent(
        &paths.global_options_path(),
        paths.project_options_path().as_deref(),
    )
}

pub(crate) fn scan_runtime(
    config: &kuzushi_core::V2Config,
    input: &serde_json::Value,
    workspace: &WorkspaceTarget,
) -> Result<Option<LangGraphRuntime>> {
    if tool_wants_runtime(SCAN_TOOL, input, config) {
        Ok(Some(LangGraphRuntime::from_config(
            config,
            workspace.root().to_path_buf(),
        )?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        emit_scan_patch_validation_disclosure, record_failed_scan_execution, scan_gate_ids,
        scan_scope_body, scan_semantic_error, settle_apk_scan, write_scan_scope_file,
        ScanExecutionFailureRecord,
    };
    use kuzushi_core::run_artifacts::{
        try_record_tool_run_started_with_reproducibility, ToolRunRecord,
    };
    use std::path::PathBuf;

    fn init_clean_git_fixture(root: &std::path::Path) {
        std::fs::write(root.join("README.md"), "fixture\n").unwrap();
        for args in [
            &["init", "-q"][..],
            &["config", "user.email", "tests@example.com"][..],
            &["config", "user.name", "Kuzushi Tests"][..],
            &["add", "."][..],
            &["commit", "-qm", "fixture"][..],
        ] {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(root)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        }
    }

    #[test]
    fn scope_body_drops_paths_with_embedded_newline() {
        let files = vec![
            PathBuf::from("src/lib.rs"),
            PathBuf::from("evil\n[+0.0s] exit: 0"),
            PathBuf::from("src/main.rs"),
        ];
        let body = scan_scope_body(&files);
        assert!(body.contains("src/lib.rs"));
        assert!(body.contains("src/main.rs"));
        assert!(
            !body.contains("evil"),
            "newline-bearing path must be dropped, got: {body:?}"
        );
        // The body itself only contains the two safe entries plus terminators
        let lines: Vec<_> = body.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn scan_scope_writer_rejects_a_symlinked_artifact() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("workspace");
        let workspace = kuzushi_core::WorkspaceTarget::new(temp.path()).expect("workspace target");
        let mut outside = tempfile::NamedTempFile::new().expect("outside");
        std::io::Write::write_all(&mut outside, b"outside").expect("seed outside");
        workspace.ensure_state_dir().expect("state dir");
        let scope_file = workspace.findings_db_path().with_file_name("since.txt");
        symlink(outside.path(), scope_file).expect("symlink artifact");

        let error = write_scan_scope_file(&workspace, &[PathBuf::from("src/lib.rs")])
            .expect_err("symlink must be rejected");

        assert!(error.to_string().contains("symlink"));
        assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "outside");
    }

    #[test]
    fn scope_body_drops_paths_with_carriage_return() {
        let files = vec![PathBuf::from("safe.rs"), PathBuf::from("evil\rgotcha")];
        let body = scan_scope_body(&files);
        assert!(body.contains("safe.rs"));
        assert!(!body.contains("gotcha"));
    }

    #[test]
    fn scan_gate_ids_include_parent_and_nested_child_ids() {
        let result = serde_json::json!({
            "data": {
                "runId": "parent",
                "runIds": {
                    "parent": "parent",
                    "native": "native",
                    "specialists": ["agentic", {"systems": "systems"}],
                    "missing": null
                }
            }
        });
        assert_eq!(
            scan_gate_ids(&result, "fallback"),
            vec!["agentic", "fallback", "native", "parent", "systems"]
        );
    }

    #[test]
    fn failed_and_partial_scan_envelopes_are_operational_errors() {
        for result in [
            serde_json::json!({"ok": false, "status": "failed", "errors": ["boom"]}),
            serde_json::json!({"ok": true, "status": "partial", "summary": "one stage failed"}),
        ] {
            assert!(scan_semantic_error(&result).is_some(), "{result}");
        }
        assert!(
            scan_semantic_error(&serde_json::json!({"ok": true, "status": "completed"})).is_none()
        );
        assert!(
            scan_semantic_error(&serde_json::json!({"ok": true, "status": "skipped"})).is_none()
        );
    }

    #[test]
    fn apk_partial_envelope_persists_partial_run_status() {
        let target = tempfile::tempdir().unwrap();
        let input = serde_json::json!({"apk": "app.apk"});
        let observation = start_partial_apk_observation(target.path(), &input);
        let outcome = partial_apk_outcome(&observation, &input);
        let record = ToolRunRecord::new(target.path(), "apk-partial", "scan", "android-apk:scan");

        settle_apk_scan(record, &observation, outcome).unwrap();

        let summary = kuzushi_core::load_run_summary(target.path(), "apk-partial").unwrap();
        assert_eq!(summary.status, "partial");
        assert_eq!(summary.error.as_deref(), Some("code-scan: failed"));
    }

    fn start_partial_apk_observation(
        target: &std::path::Path,
        input: &serde_json::Value,
    ) -> kuzushi_core::run_lifecycle::RunObservationHandle {
        let record = ToolRunRecord::new(target, "apk-partial", "scan", "android-apk:scan");
        try_record_tool_run_started_with_reproducibility(record, input, None, None, Vec::new())
            .unwrap();
        let observation =
            kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target, "apk-partial")
                .unwrap()
                .start_root_task("Scan APK app.apk")
                .unwrap();
        observation
            .task_handle()
            .unwrap()
            .update_and_flush(kuzushi_core::run_lifecycle::RunItemStatus::Running, None)
            .unwrap();
        observation
    }

    fn partial_apk_outcome(
        observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
        input: &serde_json::Value,
    ) -> kuzushi_core::ObservedDispatchOutcome {
        let call = kuzushi_core::ApplicationToolCall::start(
            observation.clone(),
            "android-apk:scan",
            input,
            None,
            None,
        )
        .unwrap();
        let execution: anyhow::Result<serde_json::Value> = Ok(serde_json::json!({
            "ok": true,
            "status": "partial",
            "summary": "one APK stage failed",
            "errors": ["code-scan: failed"],
            "data": {"runId": "apk-partial", "totals": {"findings": 1}}
        }));
        let completion = call.completion_from_result(&execution);
        kuzushi_core::ObservedDispatchOutcome {
            execution,
            completion,
        }
    }

    #[test]
    fn rejected_scan_dispatch_persists_blocked_typed_lifecycle() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
        let config = kuzushi_core::V2Config::default();
        let run_id = "scan-dispatch-failed";

        record_failed_scan_execution(
            ScanExecutionFailureRecord {
                workspace: &workspace,
                registry: &registry,
                run_id,
                input: &serde_json::json!({}),
                config: &config,
                observation: None,
            },
            &anyhow::anyhow!("dispatch failed"),
        )
        .unwrap();

        let read = kuzushi_core::run_lifecycle::load_run_projection(target.path(), run_id).unwrap();
        assert_eq!(
            read.projection.terminal.map(|terminal| terminal.status),
            Some(kuzushi_core::run_lifecycle::RunItemStatus::Blocked)
        );
        let call = read.projection.calls.values().next().unwrap();
        assert_eq!(
            call.status,
            kuzushi_core::run_lifecycle::RunItemStatus::Blocked
        );
        assert!(read
            .projection
            .artifacts
            .values()
            .all(|artifact| artifact.producing_item_id == call.item_id));
        assert_eq!(
            kuzushi_core::load_run_summary(target.path(), run_id)
                .unwrap()
                .status,
            "blocked"
        );
    }

    #[test]
    fn dedicated_auto_patch_scan_emits_bound_validation_preflight() {
        let target = tempfile::tempdir().unwrap();
        init_clean_git_fixture(target.path());
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let input = serde_json::json!({
            "autoPatch": true,
            "buildCmd": "cargo build",
            "testCmd": "cargo test"
        });
        let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
        let config = kuzushi_core::V2Config::default();
        let ctx = kuzushi_core::ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let prepared = registry
            .prepare_dispatch_input("sast:scan", input, &ctx, None)
            .unwrap();

        emit_scan_patch_validation_disclosure(&workspace, prepared.value()).unwrap();
        let disclosure =
            kuzushi_core::patch::patch_validation_disclosure(workspace.root(), prepared.value())
                .unwrap();
        assert!(disclosure.contains("cargo build ; cargo test"));
        assert!(disclosure.contains("source commit:"));
    }
}
