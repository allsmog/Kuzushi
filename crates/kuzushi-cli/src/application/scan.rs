use super::scan_cancellation::{
    persisted_scan_terminal_exit_error, scan_terminal_exit_error,
    settle_scan_cancellation_observed, settle_scan_cancellation_settled, ScanSignalWatcher,
};
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
use kuzushi_core::scan::ScanCancellation;
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
    let cancellation = ScanCancellation::default();
    let _signal_watcher = ScanSignalWatcher::install(cancellation.clone());
    if is_apk_file(&target) {
        return scan_apk_command(target, json, ci, gate, &cancellation).await;
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
        &cancellation,
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
    let cancellation = ScanCancellation::default();
    let _signal_watcher = ScanSignalWatcher::install(cancellation.clone());
    execute_prepared_scan(
        prepare_scan_command_with_requested_input(&target, input, json, ci)?,
        &target,
        &task_labels,
        json,
        ci,
        gate,
        &cancellation,
    )
}

fn execute_prepared_scan(
    prepared: PreparedScanCommand,
    target: &PathBuf,
    tasks: &[String],
    json: bool,
    ci: bool,
    gate: ScanGatePolicy,
    cancellation: &ScanCancellation,
) -> Result<()> {
    ScanInvocation {
        target,
        tasks,
        json,
        ci,
        gate,
    }
    .execute(prepared, cancellation)
}

struct ScanInvocation<'a> {
    target: &'a Path,
    tasks: &'a [String],
    json: bool,
    ci: bool,
    gate: ScanGatePolicy,
}

impl ScanInvocation<'_> {
    fn execute(self, prepared: PreparedScanCommand, cancellation: &ScanCancellation) -> Result<()> {
        let PreparedScanCommand {
            workspace,
            config,
            store,
            registry,
            input,
            runtime,
            run_id,
        } = prepared;
        let runtime = runtime.map(|runtime| runtime.with_cancellation(cancellation.clone()));
        let (started, result) = begin_and_dispatch_prepared_scan(
            &self,
            &workspace,
            &store,
            &registry,
            &config,
            input,
            runtime.as_ref(),
            &run_id,
            cancellation,
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
    cancellation: &ScanCancellation,
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
    let result = dispatch_prepared_scan(
        workspace,
        store,
        registry,
        config,
        input,
        runtime,
        run_id,
        cancellation,
    );
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
    cancellation: &ScanCancellation,
) -> Result<serde_json::Value> {
    let trace = scan_trace(workspace, run_id)?;
    let ctx = ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: Some(&trace),
        cancellation: Some(cancellation),
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
        cancellation,
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
    return_persisted_scan_terminal_exit(&finish, &result)?;
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
    return_persisted_scan_terminal_exit(&finish, &result)?;
    apply_semantic_failure_gate_policy(&finish, &run_ids)?;
    Err(scan_terminal_exit_error(
        finish.workspace.root(),
        finish.fallback_run_id,
        error,
    ))
}

fn apply_semantic_failure_gate_policy(finish: &ScanFinish<'_>, run_ids: &[String]) -> Result<()> {
    apply_scan_gate_policy(
        finish.workspace,
        finish.store,
        run_ids,
        finish.fallback_run_id,
        &ScanGatePolicy {
            fail_on: None,
            sarif: finish.gate.sarif.clone(),
        },
    )
}

fn return_persisted_scan_terminal_exit(
    finish: &ScanFinish<'_>,
    result: &serde_json::Value,
) -> Result<()> {
    let message = result
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("headless scan did not complete");
    match persisted_scan_terminal_exit_error(
        finish.workspace.root(),
        finish.fallback_run_id,
        message,
    ) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn scan_semantic_error(result: &serde_json::Value) -> Option<anyhow::Error> {
    let status = kuzushi_core::tool_result_status(result);
    if !matches!(status, ToolResultStatus::Partial | ToolResultStatus::Failed) {
        return None;
    }
    if let Some(error) = first_message(result, "errors") {
        return Some(anyhow::anyhow!(error.to_string()));
    }
    // A partial scan's summary still reads "completed", so its first warning
    // (for example the engine that was skipped, and why) says what fell short.
    let partial_reason = (status == ToolResultStatus::Partial)
        .then(|| first_message(result, "warnings"))
        .flatten();
    let message = partial_reason
        .map(|warning| format!("scan partial: {warning}"))
        .or_else(|| {
            result
                .get("summary")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            let label = if status == ToolResultStatus::Partial {
                "partial"
            } else {
                "failed"
            };
            format!("scan returned status={label}")
        });
    Some(anyhow::anyhow!(message))
}

fn first_message<'a>(result: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    result.get(key)?.as_array()?.first()?.as_str()
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
    cancellation: &'a ScanCancellation,
}

enum ScanDispatchResolution {
    Observed(kuzushi_core::ObservedDispatchOutcome),
    Settled(serde_json::Value),
}

fn execute_scan_tool(execution: ScanToolExecution<'_>) -> Result<serde_json::Value> {
    let failure_input = execution.input.clone();
    let initial_observation = execution.ctx.run_observation();
    if let Some(output) = settle_scan_if_canceled(&execution, initial_observation.as_ref())? {
        return Ok(output);
    }
    let prepared = prepare_scan_for_dispatch(&execution, &failure_input)?;
    if let Some(output) = settle_scan_if_canceled(&execution, initial_observation.as_ref())? {
        return Ok(output);
    }
    let observation = running_scan_observation(&execution)?;
    let runtime = execution
        .runtime
        .map(|runtime| runtime as &dyn AgentRuntime);
    match dispatch_scan_tool(&execution, &failure_input, prepared, &observation, runtime)? {
        ScanDispatchResolution::Observed(outcome) => settle_scan_dispatch(
            execution.workspace,
            execution.run_id,
            &observation,
            outcome,
            execution.cancellation,
        ),
        ScanDispatchResolution::Settled(output) => Ok(output),
    }
}

fn settle_scan_if_canceled(
    execution: &ScanToolExecution<'_>,
    observation: Option<&RunObservationHandle>,
) -> Result<Option<serde_json::Value>> {
    let Some(disposition) = execution.cancellation.disposition() else {
        return Ok(None);
    };
    settle_scan_cancellation_observed(
        ToolRunRecord::new(
            execution.workspace.root(),
            execution.run_id,
            "scan",
            SCAN_TOOL,
        ),
        disposition,
        observation,
    )
    .map(Some)
}

fn prepare_scan_for_dispatch(
    execution: &ScanToolExecution<'_>,
    failure_input: &serde_json::Value,
) -> Result<PreparedToolInput> {
    let prepared = execution
        .registry
        .prepare_dispatch_input(SCAN_TOOL, execution.input.clone(), execution.ctx, None)
        .map_err(|error| recorded_pre_execution_scan_error(execution, failure_input, error))?;
    emit_scan_patch_validation_disclosure(execution.workspace, prepared.value())
        .map_err(|error| recorded_pre_execution_scan_error(execution, failure_input, error))?;
    Ok(prepared)
}

fn running_scan_observation(execution: &ScanToolExecution<'_>) -> Result<RunObservationHandle> {
    let observation = execution
        .ctx
        .run_observation()
        .context("scan dispatch lacks its semantic observation")?;
    observation
        .task_handle()
        .context("scan dispatch lacks its semantic task")?
        .update_and_flush(RunItemStatus::Running, None)?;
    Ok(observation)
}

fn dispatch_scan_tool(
    execution: &ScanToolExecution<'_>,
    failure_input: &serde_json::Value,
    prepared: PreparedToolInput,
    observation: &RunObservationHandle,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<ScanDispatchResolution> {
    let dispatched = execution
        .registry
        .dispatch_prepared_input_observed_with_runtime(
            authorize_headless_scan(prepared),
            execution.ctx,
            runtime,
        );
    match dispatched {
        Ok(outcome) => Ok(ScanDispatchResolution::Observed(outcome)),
        Err(error) => match settle_scan_if_canceled(execution, Some(observation))? {
            Some(output) => Ok(ScanDispatchResolution::Settled(output)),
            None => Err(recorded_pre_execution_scan_error(
                execution,
                failure_input,
                error,
            )),
        },
    }
}

fn settle_scan_dispatch(
    workspace: &WorkspaceTarget,
    run_id: &str,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    outcome: kuzushi_core::ObservedDispatchOutcome,
    cancellation: &ScanCancellation,
) -> Result<serde_json::Value> {
    let record = ToolRunRecord::new(workspace.root(), run_id, "scan", SCAN_TOOL);
    match cancellation.disposition() {
        Some(disposition) => {
            settle_scan_cancellation_settled(record, disposition, observation, outcome.completion)
        }
        None => match outcome.execution {
            Ok(output) => {
                try_record_tool_run_complete_settled(
                    record,
                    &output,
                    observation,
                    outcome.completion,
                )?;
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
    let delegated_tools = kuzushi_core::modules::sast_scan_delegated_tools(prepared.value());
    if !delegated_tools.is_empty() {
        return prepared.authorize_explicit_headless_with_delegated_tools(&delegated_tools);
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

/// Refusal to start a scan whose `--since` scope resolved to nothing.
///
/// Typed so scan preparation can report it without minting a run artifact for
/// a scan that never began, while genuine preparation failures keep recording
/// theirs. Reaches the operator through the ordinary pre-dispatch refusal
/// path: message on stderr, exit 1, no stdout envelope in any mode.
#[derive(Debug)]
pub(crate) struct ScanScopeRefused(String);

impl std::fmt::Display for ScanScopeRefused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ScanScopeRefused {}

/// The `--since` scope actually handed to the scan, after intersecting the
/// changed files with any `--paths`/`--shard` roots already on the input.
struct EffectiveSinceScope {
    paths: Vec<PathBuf>,
    diff_base: String,
    changed: usize,
    requested: Option<usize>,
}

/// Resolve `--since <ref>` into the scan scope, materialise `since.txt`, and
/// carry the resolved scope into the canonical `sast:scan` input.
///
/// Shares `changed_scan_input` with the shell's `scan since <ref>`, so both
/// modes scope the identical file set, neither writes paths the reference
/// deleted, and both refuse rather than widen when nothing changed.
pub(crate) fn apply_scan_since_scope(
    workspace: &WorkspaceTarget,
    input: &mut serde_json::Value,
    since: Option<&str>,
    include_worktree: bool,
    json: bool,
    ci: bool,
) -> Result<()> {
    let Some(since_ref) = since else {
        return Ok(());
    };
    let changed =
        kuzushi_core::workspace::changed_scan_input(workspace.root(), since_ref, include_worktree)
            .with_context(|| format!("--since {since_ref:?} failed"))?;
    let scope = resolve_effective_since_scope(changed, input, since_ref, include_worktree)?;
    write_scan_scope_file(workspace, &scope.paths)?;
    set_scan_paths(input, &scope.paths);
    set_scan_diff_base(input, &scope.diff_base)?;
    emit_scan_scope_line(&scope, since_ref, include_worktree, json, ci);
    Ok(())
}

/// Intersect the changed files with any requested `paths` roots, or refuse.
///
/// Refusing is the point: an empty scope used to leave an empty `since.txt`,
/// which downstream reads as "no scope file" and widens to the whole target —
/// the opposite of what `--since` asked for.
fn resolve_effective_since_scope(
    changed: Option<kuzushi_core::workspace::ChangedScanScope>,
    input: &serde_json::Value,
    since_ref: &str,
    include_worktree: bool,
) -> Result<EffectiveSinceScope> {
    let requested = requested_scan_roots(input);
    let scope = changed.map(|changed| EffectiveSinceScope {
        changed: changed.paths.len(),
        paths: retain_requested_roots(&changed.paths, requested.as_deref()),
        requested: requested.as_ref().map(Vec::len),
        diff_base: changed.diff_base,
    });
    match scope {
        Some(scope) if !scope.paths.is_empty() => Ok(scope),
        scope => Err(refuse_empty_since_scope(
            since_ref,
            include_worktree,
            scope.is_some(),
        )),
    }
}

fn refuse_empty_since_scope(
    since_ref: &str,
    include_worktree: bool,
    narrowed_away: bool,
) -> anyhow::Error {
    let subject = if narrowed_away {
        "no existing changed files inside the requested paths scope"
    } else {
        "no existing changed files to scan"
    };
    let hint = if include_worktree {
        ""
    } else {
        "; pass --include-worktree to include uncommitted changes"
    };
    anyhow::Error::new(ScanScopeRefused(format!(
        "--since {since_ref}: {subject}{hint}"
    )))
}

/// Workspace-relative path roots already on the input from `--paths` or
/// `--shard`. `None` means no scope was requested; `Some(_)` always narrows,
/// so an unusable root fails closed instead of widening back to every change.
fn requested_scan_roots(input: &serde_json::Value) -> Option<Vec<PathBuf>> {
    let values = input.get("paths")?.as_array()?;
    Some(
        values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .filter_map(normalized_scan_root)
            .collect(),
    )
}

/// Target-relative normalization for prefix comparison against git's
/// target-relative diff output. Absolute or parent-escaping roots cannot name
/// a diff path, so they are dropped rather than matched loosely.
fn normalized_scan_root(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim().trim_end_matches('/');
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
    let path = Path::new(trimmed);
    let escapes = path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir));
    if trimmed.is_empty() || path.is_absolute() || escapes {
        return None;
    }
    Some(path.to_path_buf())
}

/// `Path::starts_with` is component-wise, so root `src` covers `src/lib.rs`
/// and the file `src/lib.rs` covers itself, while `srclib/x` stays out.
fn retain_requested_roots(changed: &[PathBuf], roots: Option<&[PathBuf]>) -> Vec<PathBuf> {
    let Some(roots) = roots else {
        return changed.to_vec();
    };
    changed
        .iter()
        .filter(|path| roots.iter().any(|root| path.starts_with(root)))
        .cloned()
        .collect()
}

/// `paths` is a declared `sast:scan` option, and writing the effective scope
/// there is what makes `--since` narrow every engine — as the shell's `scan
/// since` already does — rather than only the ones that read `since.txt`.
fn set_scan_paths(input: &mut serde_json::Value, paths: &[PathBuf]) {
    let Some(object) = input.as_object_mut() else {
        return;
    };
    let rendered = paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    object.insert("paths".to_string(), serde_json::json!(rendered));
}

/// `diffBase` is a declared `sast:scan` option; setting it here is what makes
/// `--since` a shorthand for the same tool input the shell submits, instead of
/// a CLI-only scope file. A different `diffBase` already on the input is a
/// contradiction, not something for `--since` to win or lose silently.
fn set_scan_diff_base(input: &mut serde_json::Value, diff_base: &str) -> Result<()> {
    let Some(object) = input.as_object_mut() else {
        return Ok(());
    };
    if let Some(existing) = existing_diff_base(object) {
        anyhow::ensure!(
            existing == diff_base,
            "--since {diff_base} conflicts with input diffBase {existing}"
        );
        return Ok(());
    }
    object.insert("diffBase".to_string(), serde_json::json!(diff_base));
    Ok(())
}

/// Both the canonical key and its declared `diff_base` alias, since raw JSON
/// scan input may carry either.
fn existing_diff_base(object: &serde_json::Map<String, serde_json::Value>) -> Option<&str> {
    ["diffBase", "diff_base"]
        .iter()
        .find_map(|key| object.get(*key).and_then(serde_json::Value::as_str))
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

fn emit_scan_scope_line(
    scope: &EffectiveSinceScope,
    since_ref: &str,
    include_worktree: bool,
    json: bool,
    ci: bool,
) {
    if json || ci {
        return;
    }
    eprintln!(
        "{}",
        scan_scope_line(scope, since_ref, scan_worktree_suffix(include_worktree))
    );
}

/// Discloses the intersection when `--paths`/`--shard` also narrowed the run,
/// so the operator can see which of the two scopes dropped a file.
fn scan_scope_line(scope: &EffectiveSinceScope, since_ref: &str, suffix: &str) -> String {
    match scope.requested {
        Some(requested) => format!(
            "scope: {} files since {since_ref} ∩ {requested} requested → {}",
            scope.changed,
            scope.paths.len()
        ),
        None => format!("scope: {} files since {since_ref} {suffix}", scope.changed),
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

struct PreparedApkScan {
    workspace: WorkspaceTarget,
    config: kuzushi_core::V2Config,
    store: FindingStore,
    registry: ModuleRegistry,
    run_id: String,
    observation: RunObservationHandle,
    trace: TraceHandle,
    input: serde_json::Value,
}

async fn scan_apk_command(
    apk: PathBuf,
    json: bool,
    ci: bool,
    gate: ScanGatePolicy,
    cancellation: &ScanCancellation,
) -> Result<()> {
    let scan = prepare_apk_scan(&apk)?;
    let started = std::time::Instant::now();
    emit_scan_ci_start(ci, started, &apk, &scan.config, &[]);
    let result = execute_apk_scan(&scan, cancellation);
    finish_scan_execution(
        ScanFinish {
            workspace: &scan.workspace,
            store: &scan.store,
            fallback_run_id: &scan.run_id,
            json,
            ci,
            started,
            gate: &gate,
        },
        result,
    )
}

fn prepare_apk_scan(apk: &Path) -> Result<PreparedApkScan> {
    let workspace_dir = apk_workspace_dir(apk)?;
    let workspace = WorkspaceTarget::new(&workspace_dir)?;
    let config = super::config_diagnostics::load_cli_config(Some(workspace.root()))?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let registry = ModuleRegistry::with_v2_builtins();
    let run_id = new_run_id("scan");
    let observation = start_apk_scan_observation(&workspace, &run_id, apk)?;
    let trace = observation.trace_handle();
    let input = prepare_apk_scan_input(
        apk,
        &workspace_dir,
        &workspace,
        &config,
        &store,
        &registry,
        &run_id,
        &trace,
    )?;
    Ok(PreparedApkScan {
        workspace,
        config,
        store,
        registry,
        run_id,
        observation,
        trace,
        input,
    })
}

fn execute_apk_scan(
    scan: &PreparedApkScan,
    cancellation: &ScanCancellation,
) -> Result<serde_json::Value> {
    let record = apk_scan_record(scan);
    record_apk_scan_started(record, &scan.input, &scan.config, &scan.registry)?;
    if let Some(disposition) = cancellation.disposition() {
        return settle_scan_cancellation_observed(record, disposition, Some(&scan.observation));
    }
    mark_apk_scan_running(&scan.observation)?;
    match dispatch_apk_scan(
        &scan.workspace,
        &scan.store,
        &scan.config,
        &scan.registry,
        scan.input.clone(),
        &scan.trace,
        cancellation,
    ) {
        Ok(outcome) => settle_apk_scan(record, &scan.observation, outcome, cancellation),
        Err(error) => settle_apk_dispatch_error(record, &scan.observation, cancellation, error),
    }
}

fn apk_scan_record(scan: &PreparedApkScan) -> ToolRunRecord<'_> {
    ToolRunRecord::new(
        scan.workspace.root(),
        &scan.run_id,
        "scan",
        "android-apk:scan",
    )
}

fn settle_apk_dispatch_error(
    record: ToolRunRecord<'_>,
    observation: &RunObservationHandle,
    cancellation: &ScanCancellation,
    error: anyhow::Error,
) -> Result<serde_json::Value> {
    match cancellation.disposition() {
        Some(disposition) => {
            settle_scan_cancellation_observed(record, disposition, Some(observation))
        }
        None => Err(error),
    }
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
    let ctx = scan_tool_context(workspace, config, store, trace, None);
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
    cancellation: &ScanCancellation,
) -> Result<kuzushi_core::ObservedDispatchOutcome> {
    let ctx = scan_tool_context(workspace, config, store, trace, Some(cancellation));
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
    cancellation: Option<&'a ScanCancellation>,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: Some(trace),
        cancellation,
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
    cancellation: &ScanCancellation,
) -> Result<serde_json::Value> {
    match cancellation.disposition() {
        Some(disposition) => {
            settle_scan_cancellation_settled(record, disposition, observation, outcome.completion)
        }
        None => match outcome.execution {
            Ok(output) => {
                try_record_tool_run_complete_settled(
                    record,
                    &output,
                    observation,
                    outcome.completion,
                )?;
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
        apply_scan_since_scope, apply_semantic_failure_gate_policy,
        emit_scan_patch_validation_disclosure, execute_scan_tool, finish_completed_scan,
        record_failed_scan_execution, requested_scan_roots, retain_requested_roots, scan_gate_ids,
        scan_scope_body, scan_scope_line, scan_semantic_error, set_scan_diff_base, settle_apk_scan,
        settle_scan_cancellation_observed, settle_scan_dispatch, write_scan_scope_file,
        EffectiveSinceScope, ScanExecutionFailureRecord, ScanFinish, ScanGatePolicy,
        ScanScopeRefused, ScanToolExecution,
    };
    use crate::application::run_exit::RunCommandExit;
    use kuzushi_core::run_artifacts::{
        try_record_tool_run_started_with_reproducibility, ToolRunRecord,
    };
    use kuzushi_core::scan::ScanCancellation;
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

    /// `--since` must scope exactly what the shell's `scan since` scopes:
    /// files that still exist, on `paths` and `diffBase` of the canonical
    /// tool input, so every engine sees the same narrowing.
    #[cfg(unix)]
    #[test]
    fn since_scope_drops_deleted_files_and_carries_diff_base() {
        let temp = tempfile::tempdir().expect("workspace");
        let root = temp.path();
        std::fs::write(root.join("keep.rs"), "fn keep() {}\n").unwrap();
        std::fs::write(root.join("gone.rs"), "fn gone() {}\n").unwrap();
        init_clean_git_fixture(root);
        let base = git_output(root, &["rev-parse", "HEAD"]);

        std::fs::write(root.join("keep.rs"), "fn keep2() {}\n").unwrap();
        std::fs::remove_file(root.join("gone.rs")).unwrap();
        git_output(root, &["add", "-A"]);
        git_output(root, &["commit", "-qm", "edit and delete"]);

        let workspace = kuzushi_core::WorkspaceTarget::new(root).expect("workspace target");
        workspace.ensure_state_dir().expect("state dir");
        let mut input = serde_json::json!({ "mode": "standard" });
        apply_scan_since_scope(&workspace, &mut input, Some(&base), false, true, false)
            .expect("since scope");

        let scope_file = workspace.findings_db_path().with_file_name("since.txt");
        let body = std::fs::read_to_string(scope_file).expect("since.txt");
        let lines: Vec<_> = body.lines().filter(|line| !line.is_empty()).collect();
        assert_eq!(lines, vec!["keep.rs"], "deleted paths must not be scoped");
        assert_eq!(input["diffBase"], serde_json::json!(base));
        assert_eq!(input["paths"], serde_json::json!(["keep.rs"]));
    }

    /// A `--since` reference that changed nothing must refuse, not fall back
    /// to the whole target through an empty scope file.
    #[cfg(unix)]
    #[test]
    fn since_scope_without_changes_refuses_the_scan() {
        let temp = tempfile::tempdir().expect("workspace");
        let root = temp.path();
        init_clean_git_fixture(root);
        let base = git_output(root, &["rev-parse", "HEAD"]);

        let workspace = kuzushi_core::WorkspaceTarget::new(root).expect("workspace target");
        workspace.ensure_state_dir().expect("state dir");
        let mut input = serde_json::json!({ "mode": "standard" });
        let error = apply_scan_since_scope(&workspace, &mut input, Some(&base), false, true, false)
            .expect_err("an empty since scope must refuse");

        assert!(
            error.downcast_ref::<ScanScopeRefused>().is_some(),
            "refusal must be typed so preparation records no run: {error:#}"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "--since {base}: no existing changed files to scan; \
                 pass --include-worktree to include uncommitted changes"
            )
        );
        assert!(input.get("diffBase").is_none());
        assert!(input.get("paths").is_none());
    }

    /// With `--include-worktree` already set there is nothing further to
    /// include, so the refusal must not suggest it.
    #[cfg(unix)]
    #[test]
    fn since_scope_refusal_drops_the_worktree_hint_when_already_included() {
        let temp = tempfile::tempdir().expect("workspace");
        let root = temp.path();
        init_clean_git_fixture(root);
        let base = git_output(root, &["rev-parse", "HEAD"]);

        let workspace = kuzushi_core::WorkspaceTarget::new(root).expect("workspace target");
        workspace.ensure_state_dir().expect("state dir");
        let mut input = serde_json::json!({});
        let error = apply_scan_since_scope(&workspace, &mut input, Some(&base), true, true, false)
            .expect_err("an empty since scope must refuse");

        assert_eq!(
            error.to_string(),
            format!("--since {base}: no existing changed files to scan")
        );
    }

    /// `--since` combined with `--paths`/`--shard` narrows to the
    /// intersection; it never widens back to either scope alone.
    #[cfg(unix)]
    #[test]
    fn since_scope_intersects_requested_path_roots() {
        let temp = tempfile::tempdir().expect("workspace");
        let root = temp.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn a() {}\n").unwrap();
        std::fs::write(root.join("docs/readme.md"), "a\n").unwrap();
        init_clean_git_fixture(root);
        let base = git_output(root, &["rev-parse", "HEAD"]);

        std::fs::write(root.join("src/lib.rs"), "fn b() {}\n").unwrap();
        std::fs::write(root.join("docs/readme.md"), "b\n").unwrap();
        git_output(root, &["add", "-A"]);
        git_output(root, &["commit", "-qm", "touch both"]);

        let workspace = kuzushi_core::WorkspaceTarget::new(root).expect("workspace target");
        workspace.ensure_state_dir().expect("state dir");
        let mut input = serde_json::json!({ "paths": ["./src/"] });
        apply_scan_since_scope(&workspace, &mut input, Some(&base), false, true, false)
            .expect("since scope");

        assert_eq!(input["paths"], serde_json::json!(["src/lib.rs"]));
        let scope_file = workspace.findings_db_path().with_file_name("since.txt");
        let body = std::fs::read_to_string(scope_file).expect("since.txt");
        assert_eq!(
            body.lines().filter(|line| !line.is_empty()).count(),
            1,
            "since.txt must carry the post-intersection scope: {body:?}"
        );
    }

    /// An empty intersection is still an empty scope, so it refuses too.
    #[cfg(unix)]
    #[test]
    fn since_scope_refuses_an_empty_intersection() {
        let temp = tempfile::tempdir().expect("workspace");
        let root = temp.path();
        std::fs::write(root.join("app.rs"), "fn a() {}\n").unwrap();
        init_clean_git_fixture(root);
        let base = git_output(root, &["rev-parse", "HEAD"]);

        std::fs::write(root.join("app.rs"), "fn b() {}\n").unwrap();
        git_output(root, &["add", "-A"]);
        git_output(root, &["commit", "-qm", "touch app"]);

        let workspace = kuzushi_core::WorkspaceTarget::new(root).expect("workspace target");
        workspace.ensure_state_dir().expect("state dir");
        let mut input = serde_json::json!({ "paths": ["vendor"] });
        let error = apply_scan_since_scope(&workspace, &mut input, Some(&base), true, true, false)
            .expect_err("an empty intersection must refuse");

        assert!(error.downcast_ref::<ScanScopeRefused>().is_some());
        assert_eq!(
            error.to_string(),
            format!("--since {base}: no existing changed files inside the requested paths scope")
        );
    }

    /// A `paths` root that cannot name a target-relative diff path must fail
    /// closed, never fall back to every changed file.
    #[test]
    fn unusable_requested_roots_narrow_to_nothing_rather_than_widening() {
        let changed = vec![PathBuf::from("src/lib.rs")];
        let requested = requested_scan_roots(&serde_json::json!({ "paths": ["/abs", "../up"] }))
            .expect("paths key present");
        assert!(requested.is_empty());
        assert!(retain_requested_roots(&changed, Some(&requested)).is_empty());
        assert_eq!(
            retain_requested_roots(&changed, None),
            changed,
            "no requested scope must leave the changed set intact"
        );
    }

    #[test]
    fn requested_roots_match_whole_path_components_only() {
        let changed = vec![
            PathBuf::from("src/lib.rs"),
            PathBuf::from("srclib/other.rs"),
            PathBuf::from("src"),
        ];
        let roots = vec![PathBuf::from("src")];
        assert_eq!(
            retain_requested_roots(&changed, Some(&roots)),
            vec![PathBuf::from("src/lib.rs"), PathBuf::from("src")]
        );
    }

    #[test]
    fn diff_base_conflict_is_explicit_and_equal_values_are_accepted() {
        let mut conflicting = serde_json::json!({ "diffBase": "HEAD~9" });
        let error = set_scan_diff_base(&mut conflicting, "HEAD~1").expect_err("conflict");
        assert_eq!(
            error.to_string(),
            "--since HEAD~1 conflicts with input diffBase HEAD~9"
        );

        let mut aliased = serde_json::json!({ "diff_base": "HEAD~2" });
        assert!(set_scan_diff_base(&mut aliased, "HEAD~1").is_err());

        let mut agreeing = serde_json::json!({ "diffBase": "HEAD~1" });
        set_scan_diff_base(&mut agreeing, "HEAD~1").expect("equal values agree");
        assert_eq!(agreeing["diffBase"], serde_json::json!("HEAD~1"));
    }

    #[test]
    fn scope_line_discloses_the_intersection_when_paths_were_requested() {
        let intersected = EffectiveSinceScope {
            paths: vec![PathBuf::from("src/lib.rs")],
            diff_base: "HEAD~1".to_string(),
            changed: 4,
            requested: Some(2),
        };
        assert_eq!(
            scan_scope_line(&intersected, "HEAD~1", "(+worktree)"),
            "scope: 4 files since HEAD~1 ∩ 2 requested → 1"
        );

        let plain = EffectiveSinceScope {
            requested: None,
            ..intersected
        };
        assert_eq!(
            scan_scope_line(&plain, "HEAD~1", "(+worktree)"),
            "scope: 4 files since HEAD~1 (+worktree)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn since_scope_rejects_an_unknown_reference() {
        let temp = tempfile::tempdir().expect("workspace");
        let root = temp.path();
        init_clean_git_fixture(root);
        let workspace = kuzushi_core::WorkspaceTarget::new(root).expect("workspace target");
        workspace.ensure_state_dir().expect("state dir");
        let mut input = serde_json::json!({});

        let error = apply_scan_since_scope(
            &workspace,
            &mut input,
            Some("no-such-ref"),
            false,
            true,
            false,
        )
        .expect_err("unknown ref must fail");

        assert!(
            format!("{error:#}").contains("git diff failed"),
            "unexpected error: {error:#}"
        );
    }

    fn git_output(root: &std::path::Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?} failed");
        String::from_utf8(output.stdout).unwrap().trim().to_string()
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
    fn cancellation_before_preparation_settles_without_dispatch() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
        let config = kuzushi_core::V2Config::default();
        let cancellation = ScanCancellation::default();
        cancellation.cancel();
        let run_id = "scan-canceled-before-preparation";
        let input = serde_json::json!({"runId": run_id});
        try_record_tool_run_started_with_reproducibility(
            ToolRunRecord::new(target.path(), run_id, "scan", "sast:scan"),
            &input,
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let ctx = kuzushi_core::ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: Some(&cancellation),
            authorization: Default::default(),
        };

        let output = execute_scan_tool(ScanToolExecution {
            registry: &registry,
            input,
            ctx: &ctx,
            runtime: None,
            workspace: &workspace,
            run_id,
            config: &config,
            cancellation: &cancellation,
        })
        .unwrap();

        assert_eq!(output["status"], "canceled");
    }

    #[test]
    fn persisted_cancellation_precedes_post_scan_gate_failures() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
        let run_id = "scan-canceled-before-gates";
        let input = serde_json::json!({"runId": run_id});
        let record = ToolRunRecord::new(target.path(), run_id, "scan", "sast:scan");
        try_record_tool_run_started_with_reproducibility(record, &input, None, None, Vec::new())
            .unwrap();
        let observation =
            kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target.path(), run_id)
                .unwrap()
                .start_root_task("Run the accepted Scan plan")
                .unwrap();
        let result = settle_scan_cancellation_observed(
            record,
            kuzushi_core::scan::CancellationDisposition::Canceled,
            Some(&observation),
        )
        .unwrap();
        let sarif = target.path().join("missing-parent").join("report.sarif");
        let gate = ScanGatePolicy {
            fail_on: None,
            sarif: Some(sarif.clone()),
        };

        let error = finish_completed_scan(
            ScanFinish {
                workspace: &workspace,
                store: &store,
                fallback_run_id: run_id,
                json: true,
                ci: false,
                started: std::time::Instant::now(),
                gate: &gate,
            },
            result,
            vec![run_id.to_string()],
            std::time::Duration::ZERO,
        )
        .expect_err("persisted cancellation must stop before post-scan gates");

        let exit = error
            .downcast::<RunCommandExit>()
            .expect("persisted cancellation must select a typed batch exit");
        assert_eq!(exit.code(), 130);
        assert!(
            !sarif.exists(),
            "SARIF export must not run after cancellation"
        );
    }

    #[test]
    fn semantic_failure_gate_attempts_requested_sarif_export() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
        let blocked_parent = target.path().join("not-a-directory");
        std::fs::write(&blocked_parent, "blocks SARIF parent creation").unwrap();
        let gate = ScanGatePolicy {
            fail_on: None,
            sarif: Some(blocked_parent.join("report.sarif")),
        };
        let finish = ScanFinish {
            workspace: &workspace,
            store: &store,
            fallback_run_id: "semantic-failure",
            json: true,
            ci: false,
            started: std::time::Instant::now(),
            gate: &gate,
        };

        apply_semantic_failure_gate_policy(&finish, &["semantic-failure".to_string()])
            .expect_err("semantic failure must still attempt requested SARIF export");
    }

    #[test]
    fn rejected_scan_input_persists_a_blocked_terminal_run() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
        let registry = kuzushi_core::ModuleRegistry::with_v2_builtins();
        let config = kuzushi_core::V2Config::default();
        let cancellation = ScanCancellation::default();
        let run_id = "scan-rejected-before-dispatch";
        let input = serde_json::json!({"unknownOption": true});
        let ctx = kuzushi_core::ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: Some(&cancellation),
            authorization: Default::default(),
        };

        let error = execute_scan_tool(ScanToolExecution {
            registry: &registry,
            input,
            ctx: &ctx,
            runtime: None,
            workspace: &workspace,
            run_id,
            config: &config,
            cancellation: &cancellation,
        })
        .expect_err("unknown input must fail before dispatch");

        assert!(error.to_string().contains("unknown option"));
        assert_eq!(
            kuzushi_core::load_run_summary(target.path(), run_id)
                .unwrap()
                .status,
            "blocked"
        );
    }

    #[test]
    fn canceled_scan_dispatch_cannot_be_persisted_as_completed() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let run_id = "scan-cancel-settlement";
        let input = serde_json::json!({"runId": run_id});
        let record = ToolRunRecord::new(target.path(), run_id, "scan", "sast:scan");
        try_record_tool_run_started_with_reproducibility(record, &input, None, None, Vec::new())
            .unwrap();
        let observation =
            kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target.path(), run_id)
                .unwrap()
                .start_root_task("Run the accepted Scan plan")
                .unwrap();
        observation
            .task_handle()
            .unwrap()
            .update_and_flush(kuzushi_core::run_lifecycle::RunItemStatus::Running, None)
            .unwrap();
        let call = kuzushi_core::ApplicationToolCall::start(
            observation.clone(),
            "sast:scan",
            &input,
            None,
            None,
        )
        .unwrap();
        let execution: anyhow::Result<serde_json::Value> = Ok(serde_json::json!({
            "ok": true,
            "status": "completed",
            "summary": "must not outrun cancellation",
            "data": {"runId": run_id}
        }));
        let completion = call.completion_from_result(&execution);
        let cancellation = ScanCancellation::default();
        cancellation.cancel();

        let output = settle_scan_dispatch(
            &workspace,
            run_id,
            &observation,
            kuzushi_core::ObservedDispatchOutcome {
                execution,
                completion,
            },
            &cancellation,
        )
        .unwrap();

        assert_eq!(output["status"], "canceled");
        assert_eq!(
            kuzushi_core::load_run_summary(target.path(), run_id)
                .unwrap()
                .status,
            "canceled"
        );
        let projection = kuzushi_core::run_lifecycle::load_run_projection(target.path(), run_id)
            .unwrap()
            .projection;
        assert_eq!(
            projection.terminal.map(|terminal| terminal.status),
            Some(kuzushi_core::run_lifecycle::RunItemStatus::Canceled)
        );
        assert_eq!(
            projection.calls.values().next().map(|call| call.status),
            Some(kuzushi_core::run_lifecycle::RunItemStatus::Canceled)
        );
    }

    #[test]
    fn apk_partial_envelope_persists_partial_run_status() {
        let target = tempfile::tempdir().unwrap();
        let input = serde_json::json!({"apk": "app.apk"});
        let observation = start_partial_apk_observation(target.path(), &input);
        let outcome = partial_apk_outcome(&observation, &input);
        let record = ToolRunRecord::new(target.path(), "apk-partial", "scan", "android-apk:scan");
        let cancellation = ScanCancellation::default();

        settle_apk_scan(record, &observation, outcome, &cancellation).unwrap();

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
