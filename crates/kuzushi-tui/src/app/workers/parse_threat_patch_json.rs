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
    let suppression_summary = invocation.prepare_workspace_state()?;
    if !suppression_summary.is_noop() {
        sink.send(ShellEvent::Scan(ScanEvent::Stage(format!(
            "suppressions reconciled: {} added, {} expired, {} removed",
            suppression_summary.added, suppression_summary.expired, suppression_summary.removed
        ))));
    }
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
    cancellation: ScanCancellation,
}

impl RegistryScanInvocation {
    fn prepare_workspace_state(
        &self,
    ) -> Result<kuzushi_core::suppressions::SuppressionReconcileSummary> {
        kuzushi_core::scan::prepare_scan_workspace_state(&self.workspace, &self.store)
    }

    fn execute(self, registry: ModuleRegistry) -> Result<serde_json::Value> {
        let RegistryScanInvocation {
            workspace,
            store,
            input,
            config,
            runtime,
            trace_handle,
            cancellation,
        } = self;
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: Some(&trace_handle),
            cancellation: Some(&cancellation),
            authorization: Default::default(),
        };
        let prepared = registry.prepare_dispatch_input("sast:scan", input, &ctx, None)?;
        let prepared = if prepared
            .value()
            .get("autoPatch")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            prepared.authorize_interactive_with_delegated_tools(&["patch:finding"])
        } else {
            prepared
        };
        registry.dispatch_prepared_input_with_runtime(
            prepared,
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
    let runtime = registry_scan_runtime(&input, &config, thinking_level, cancel, workspace.root())?;
    Ok(RegistryScanInvocation {
        workspace,
        store,
        input,
        config,
        runtime,
        trace_handle,
        cancellation: cancel.clone(),
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
    workspace_root: &std::path::Path,
) -> Result<Option<LangGraphRuntime>> {
    if !kuzushi_core::modules::wants_sast_runtime(input) {
        return Ok(None);
    }
    Ok(Some(
        LangGraphRuntime::from_config(config, workspace_root.to_path_buf())?
            .with_thinking_level(thinking_level)
            .with_cancellation(cancel.clone()),
    ))
}

fn ensure_scan_not_cancelled(cancel: &ScanCancellation) -> Result<()> {
    if cancel.is_cancelled() {
        anyhow::bail!("scan cancelled");
    }
    Ok(())
}

fn send_registry_scan_finished(sink: &JobEventSink, result: serde_json::Value) -> Result<()> {
    sink.send(ShellEvent::Scan(ScanEvent::Finished { result }));
    Ok(())
}
