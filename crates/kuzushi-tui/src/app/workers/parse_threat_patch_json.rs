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
    let preparation = invocation.prepare_workspace_state(sink)?;
    if let Some(warning) = &preparation.tree_identity_warning {
        sink.send(ShellEvent::Scan(ScanEvent::Stage(warning.clone())));
    }
    let suppression_summary = preparation.suppressions;
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
        sink: &JobEventSink,
    ) -> Result<kuzushi_core::scan::ScanWorkspacePreparation> {
        // The identity walk hashes every file; heartbeats keep the stall
        // watchdog honest on monorepo-scale targets.
        let mut heartbeat =
            kuzushi_core::progress::HeartbeatGate::new(std::time::Duration::from_secs(5));
        let mut on_files_hashed = |files: usize| {
            if heartbeat.ready() {
                sink.send(ShellEvent::Scan(ScanEvent::Stage(format!(
                    "registering workspace tree identity · {files} files hashed"
                ))));
            }
        };
        kuzushi_core::scan::prepare_scan_workspace_state_with_observer(
            &self.workspace,
            &self.store,
            &mut on_files_hashed,
        )
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
        let prepared = prepare_interactive_scan_input(&registry, input, &ctx)?;
        let (observation, run_id) = start_interactive_scan_observation(&ctx)?;
        let outcome = registry.dispatch_prepared_input_observed_with_runtime(
            prepared,
            &ctx,
            runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
        )?;
        settle_interactive_scan(
            workspace.root(),
            &run_id,
            &observation,
            &cancellation,
            outcome,
        )
    }
}

fn start_interactive_scan_observation(
    ctx: &ToolExecutionContext<'_>,
) -> Result<(kuzushi_core::run_lifecycle::RunObservationHandle, String)> {
    let observation = ctx
        .run_observation()
        .context("interactive scan lacks its semantic observation")?;
    observation
        .task_handle()
        .context("interactive scan lacks its semantic task")?
        .update_and_flush(kuzushi_core::run_lifecycle::RunItemStatus::Running, None)?;
    let run_id = ctx
        .run_id()
        .context("interactive scan lacks its run identity")?;
    Ok((observation, run_id))
}

fn prepare_interactive_scan_input(
    registry: &ModuleRegistry,
    input: serde_json::Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<kuzushi_core::PreparedToolInput> {
    let prepared = registry.prepare_dispatch_input("sast:scan", input, ctx, None)?;
    let delegated_tools = kuzushi_core::modules::sast_scan_delegated_tools(prepared.value());
    if !delegated_tools.is_empty() {
        return Ok(prepared.authorize_interactive_with_delegated_tools(&delegated_tools));
    }
    Ok(prepared)
}

fn settle_interactive_scan(
    target: &std::path::Path,
    run_id: &str,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    cancellation: &ScanCancellation,
    outcome: kuzushi_core::ObservedDispatchOutcome,
) -> Result<serde_json::Value> {
    let record =
        kuzushi_core::run_artifacts::ToolRunRecord::new(target, run_id, "scan", "sast:scan");
    if let Some(disposition) = cancellation.disposition() {
        return settle_interactive_scan_error(
            record,
            observation,
            cancellation,
            outcome.completion,
            scan_cancellation_error(disposition),
        );
    }
    match outcome.execution {
        Ok(output) => {
            kuzushi_core::run_artifacts::try_record_tool_run_complete_settled(
                record,
                &output,
                observation,
                outcome.completion,
            )?;
            Ok(output)
        }
        Err(error) => settle_interactive_scan_error(
            record,
            observation,
            cancellation,
            outcome.completion,
            error,
        ),
    }
}

fn scan_cancellation_error(
    disposition: kuzushi_core::scan::CancellationDisposition,
) -> anyhow::Error {
    match disposition {
        kuzushi_core::scan::CancellationDisposition::Canceled => anyhow::anyhow!("scan cancelled"),
        kuzushi_core::scan::CancellationDisposition::Interrupted => {
            anyhow::anyhow!("scan interrupted")
        }
    }
}

fn settle_interactive_scan_error(
    record: kuzushi_core::run_artifacts::ToolRunRecord<'_>,
    observation: &kuzushi_core::run_lifecycle::RunObservationHandle,
    cancellation: &ScanCancellation,
    completion: kuzushi_core::PendingToolCallCompletion,
    error: anyhow::Error,
) -> Result<serde_json::Value> {
    match cancellation.disposition() {
        Some(kuzushi_core::scan::CancellationDisposition::Canceled) => {
            kuzushi_core::run_artifacts::try_record_tool_run_canceled_settled(
                record,
                &error.to_string(),
                observation,
                completion,
            )?;
        }
        Some(kuzushi_core::scan::CancellationDisposition::Interrupted) => {
            kuzushi_core::run_artifacts::try_record_tool_run_interrupted_settled(
                record,
                &error.to_string(),
                observation,
                completion,
            )?;
        }
        None => {
            kuzushi_core::run_artifacts::try_record_tool_run_failed_settled(
                record,
                &error.to_string(),
                observation,
                completion,
            )?;
        }
    }
    Err(error)
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

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::run_lifecycle::{RunItemStatus, RunItemV1};

    const RUN_ID: &str = "scan-cancel-race";

    struct CompletedScanFixture {
        target: tempfile::TempDir,
        observation: kuzushi_core::run_lifecycle::RunObservationHandle,
        cancellation: ScanCancellation,
        outcome: kuzushi_core::ObservedDispatchOutcome,
    }

    impl CompletedScanFixture {
        fn new() -> Self {
            let target = tempfile::tempdir().unwrap();
            let record = kuzushi_core::run_artifacts::ToolRunRecord::new(
                target.path(),
                RUN_ID,
                "scan",
                "sast:scan",
            );
            kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
                record,
                &serde_json::json!({}),
                None,
                None,
                Vec::new(),
            )
            .unwrap();
            let observation = test_scan_observation(target.path());
            let output = serde_json::json!({"ok": true, "status": "completed", "data": {}});
            let call = kuzushi_core::ApplicationToolCall::start(
                observation.clone(),
                "sast:scan",
                &serde_json::json!({}),
                None,
                None,
            )
            .unwrap();
            let completion = call.completion_from_result(&Ok(output.clone()));
            let cancellation = ScanCancellation::default();
            cancellation.cancel();
            Self {
                target,
                observation,
                cancellation,
                outcome: kuzushi_core::ObservedDispatchOutcome {
                    execution: Ok(output),
                    completion,
                },
            }
        }
    }

    #[test]
    fn completed_scan_result_is_canceled_before_terminal_persistence() {
        let fixture = CompletedScanFixture::new();
        let error = settle_interactive_scan(
            fixture.target.path(),
            RUN_ID,
            &fixture.observation,
            &fixture.cancellation,
            fixture.outcome,
        )
        .unwrap_err();

        assert_canceled_run(fixture.target.path(), error);
    }

    fn test_scan_observation(
        target: &std::path::Path,
    ) -> kuzushi_core::run_lifecycle::RunObservationHandle {
        let observation = kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target, RUN_ID)
            .unwrap()
            .start_root_task("Run the accepted Scan plan")
            .unwrap();
        observation
            .task_handle()
            .unwrap()
            .update_and_flush(RunItemStatus::Running, None)
            .unwrap();
        observation
    }

    fn assert_canceled_run(target: &std::path::Path, error: anyhow::Error) {
        assert_eq!(error.to_string(), "scan cancelled");
        assert_eq!(
            kuzushi_core::load_run_summary(target, RUN_ID)
                .unwrap()
                .status,
            "canceled"
        );
        let items = kuzushi_core::run_lifecycle::read_run_items(target, RUN_ID)
            .unwrap()
            .unwrap()
            .items;
        assert!(items.iter().any(|item| matches!(
            item.item,
            RunItemV1::ToolCallFinished {
                status: RunItemStatus::Canceled,
                ..
            }
        )));
        let projection = kuzushi_core::run_lifecycle::load_run_projection(target, RUN_ID)
            .unwrap()
            .projection;
        assert_eq!(
            projection.health,
            kuzushi_core::run_lifecycle::ProjectionHealth::Healthy
        );
        assert!(projection
            .calls
            .values()
            .any(|call| call.status == RunItemStatus::Canceled));
    }
}
