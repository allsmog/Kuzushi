use super::*;

mod json_patch;
pub(crate) use json_patch::{merge_json, parse_threat_patch_json};

pub(crate) fn scan_worker(
    target: PathBuf,
    db_path: PathBuf,
    sink: JobEventSink,
    cancel: ScanCancellation,
    input: serde_json::Value,
    registry: ModuleRegistry,
    config: V2Config,
    thinking_level: Option<String>,
    trace_handle: TraceHandle,
) {
    if let Err(error) = run_scan_worker(
        target,
        db_path,
        &sink,
        &cancel,
        input,
        registry,
        config,
        thinking_level,
        trace_handle,
    ) {
        sink.send(ShellEvent::Scan(ScanEvent::Failed {
            error: error.to_string(),
        }));
    }
}

pub(crate) fn run_scan_worker(
    target: PathBuf,
    db_path: PathBuf,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
    input: serde_json::Value,
    registry: ModuleRegistry,
    config: V2Config,
    thinking_level: Option<String>,
    trace_handle: TraceHandle,
) -> Result<()> {
    if cancel.is_cancelled() {
        anyhow::bail!("scan cancelled");
    }
    run_registry_scan_worker(
        target,
        db_path,
        sink,
        cancel,
        input,
        registry,
        config,
        thinking_level,
        trace_handle,
    )
}

pub(crate) fn run_registry_scan_worker(
    target: PathBuf,
    db_path: PathBuf,
    sink: &JobEventSink,
    cancel: &ScanCancellation,
    input: serde_json::Value,
    registry: ModuleRegistry,
    config: V2Config,
    thinking_level: Option<String>,
    trace_handle: TraceHandle,
) -> Result<()> {
    let invocation = prepare_registry_scan_invocation(
        target,
        db_path,
        input,
        config,
        thinking_level,
        cancel,
        trace_handle,
    )?;
    sink.send(ShellEvent::Scan(ScanEvent::Stage(
        "running sast:scan".to_string(),
    )));
    let result = invocation.execute(registry)?;
    send_registry_scan_result(cancel, sink, result)
}

struct RegistryScanInvocation {
    workspace: WorkspaceTarget,
    store: FindingStore,
    input: serde_json::Value,
    config: V2Config,
    runtime: Option<LangGraphRuntime>,
    trace_handle: TraceHandle,
}

impl RegistryScanInvocation {
    fn execute(self, registry: ModuleRegistry) -> Result<serde_json::Value> {
        let RegistryScanInvocation {
            workspace,
            store,
            input,
            config,
            runtime,
            trace_handle,
        } = self;
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&trace_handle),
        };
        registry.dispatch_prepared_tool_with_runtime(
            "sast:scan",
            input,
            &ctx,
            runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
        )
    }
}

fn prepare_registry_scan_invocation(
    target: PathBuf,
    db_path: PathBuf,
    input: serde_json::Value,
    config: V2Config,
    thinking_level: Option<String>,
    cancel: &ScanCancellation,
    trace_handle: TraceHandle,
) -> Result<RegistryScanInvocation> {
    let (workspace, store) = registry_scan_workspace_store(target, db_path)?;
    let runtime = registry_scan_runtime(&input, &config, thinking_level, cancel)?;
    Ok(RegistryScanInvocation {
        workspace,
        store,
        input,
        config,
        runtime,
        trace_handle,
    })
}

fn registry_scan_workspace_store(
    target: PathBuf,
    db_path: PathBuf,
) -> Result<(WorkspaceTarget, FindingStore)> {
    Ok((
        prepare_scan_worker_workspace(target)?,
        FindingStore::open(db_path)?,
    ))
}

fn prepare_scan_worker_workspace(target: PathBuf) -> Result<WorkspaceTarget> {
    let workspace = WorkspaceTarget::new(&target)?;
    workspace.ensure_state_dir()?;
    Ok(workspace)
}

fn send_registry_scan_result(
    cancel: &ScanCancellation,
    sink: &JobEventSink,
    result: serde_json::Value,
) -> Result<()> {
    ensure_scan_not_cancelled(cancel)?;
    send_registry_scan_finished(sink, result)
}

fn registry_scan_runtime(
    input: &serde_json::Value,
    config: &V2Config,
    thinking_level: Option<String>,
    cancel: &ScanCancellation,
) -> Result<Option<LangGraphRuntime>> {
    if !kuzushi_core::modules::wants_sast_runtime(input) {
        return Ok(None);
    }
    Ok(Some(
        LangGraphRuntime::from_config(config, scan_worker_runtime_cwd())?
            .with_thinking_level(thinking_level)
            .with_cancellation(cancel.clone()),
    ))
}

fn scan_worker_runtime_cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn ensure_scan_not_cancelled(cancel: &ScanCancellation) -> Result<()> {
    if cancel.is_cancelled() {
        anyhow::bail!("scan cancelled");
    }
    Ok(())
}

fn send_registry_scan_finished(sink: &JobEventSink, result: serde_json::Value) -> Result<()> {
    let run_id = result
        .pointer("/data/runId")
        .and_then(serde_json::Value::as_str)
        .context("sast:scan result did not include data.runId")?;
    let findings_count = result
        .pointer("/data/findingsCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    let cost_usd = kuzushi_core::run_artifacts::tool_run_output_cost_usd(&result);
    sink.send(ShellEvent::Scan(ScanEvent::Finished {
        run_id: run_id.to_string(),
        findings_count,
        cost_usd,
    }));
    Ok(())
}
