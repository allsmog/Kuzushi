use super::*;
use std::path::PathBuf;

pub(super) struct BackgroundToolRun {
    pub(super) target: PathBuf,
    pub(super) run_id: String,
    pub(super) target_label: String,
    pub(super) trace_handle: TraceHandle,
}

pub(super) struct BackgroundToolRunSeed {
    target: PathBuf,
    pub(super) run_id: String,
    target_label: String,
}

pub(super) struct BackgroundToolDispatch {
    registry: ModuleRegistry,
    pub(super) config: V2Config,
    run: BackgroundToolRun,
    ticket: JobTicket,
}

pub(super) struct BackgroundToolWorkerLaunch {
    registry: ModuleRegistry,
    config: V2Config,
    run: BackgroundToolRun,
    ticket: JobTicket,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: PreparedToolInput,
    thinking_level: Option<String>,
    authorization: ExecutionAuthorization,
}

impl BackgroundToolWorkerLaunch {
    pub(super) fn from_dispatch(
        dispatch: BackgroundToolDispatch,
        workspace: WorkspaceTarget,
        tool_name: String,
        input: PreparedToolInput,
        thinking_level: Option<String>,
        authorization: ExecutionAuthorization,
    ) -> Self {
        let BackgroundToolDispatch {
            registry,
            config,
            run,
            ticket,
        } = dispatch;
        Self {
            registry,
            config,
            run,
            ticket,
            workspace,
            tool_name,
            input,
            thinking_level,
            authorization,
        }
    }

    pub(super) fn attach_and_start(
        self,
        app: &mut ShellApp,
        status: &str,
        activity: Option<LiveActivity>,
        model_override: Option<String>,
    ) {
        let start = self.attach(app, status, activity, model_override);
        let generation = start.ticket.generation();
        let watchdog_cancel = start.ticket.cancel.clone();
        let handle = start.start();
        app.register_worker_handle_with_watchdog("tool", generation, handle, watchdog_cancel);
    }

    fn attach(
        self,
        app: &mut ShellApp,
        status: &str,
        activity: Option<LiveActivity>,
        model_override: Option<String>,
    ) -> BackgroundToolWorkerStart {
        let start = BackgroundToolWorkerStart {
            registry: self.registry,
            config: self.config,
            run: self.run,
            ticket: self.ticket,
            workspace: self.workspace,
            tool_name: self.tool_name,
            input: self.input,
            thinking_level: self.thinking_level,
            authorization: self.authorization,
        };
        app.attach_background_tool_run(
            &start.run,
            start.ticket.cancel.clone(),
            &start.tool_name,
            status,
            activity,
            model_override,
        );
        start
    }
}

struct BackgroundToolWorkerStart {
    registry: ModuleRegistry,
    config: V2Config,
    run: BackgroundToolRun,
    ticket: JobTicket,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: PreparedToolInput,
    thinking_level: Option<String>,
    authorization: ExecutionAuthorization,
}

impl BackgroundToolWorkerStart {
    fn start(self) -> std::thread::JoinHandle<()> {
        let BackgroundToolWorkerStart {
            registry,
            config,
            run,
            ticket,
            workspace,
            tool_name,
            input,
            thinking_level,
            authorization,
        } = self;
        spawn_job_worker("tool", ticket, move |sink, cancel| {
            background_tool_worker(
                registry,
                config,
                workspace,
                tool_name,
                input,
                run.run_id,
                thinking_level,
                authorization,
                sink,
                Some(run.trace_handle),
                cancel,
            )
        })
    }
}

pub(super) fn prepare_background_tool_dispatch(
    registry: &ModuleRegistry,
    config: &V2Config,
    seed: BackgroundToolRunSeed,
    ticket: JobTicket,
    trace_budget: LiveTraceBudget,
) -> BackgroundToolDispatch {
    let registry = registry.clone();
    let config = config.clone();
    let run = prepare_background_tool_run(seed, ticket.sink(), trace_budget.clone());
    BackgroundToolDispatch {
        registry,
        config,
        run,
        ticket,
    }
}

pub(super) fn persist_background_tool_run_start(
    registry: &ModuleRegistry,
    config: &V2Config,
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: &serde_json::Value,
) -> anyhow::Result<BackgroundToolRunSeed> {
    let target = workspace.root().to_path_buf();
    let run_id = new_run_id("tool");
    let target_label = target.display().to_string();
    let record =
        kuzushi_core::run_artifacts::ToolRunRecord::new(&target, &run_id, "tool", tool_name);
    kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        input,
        kuzushi_core::tool_execution_model(tool_name, input, config),
        config_hash(config).ok(),
        registry.loaded_module_specifiers(),
    )?;
    Ok(BackgroundToolRunSeed {
        target,
        run_id,
        target_label,
    })
}

fn prepare_background_tool_run(
    seed: BackgroundToolRunSeed,
    sink: JobEventSink,
    trace_budget: LiveTraceBudget,
) -> BackgroundToolRun {
    let trace_handle = background_tool_trace_handle(&seed.target, &seed.run_id, sink, trace_budget);
    BackgroundToolRun {
        target: seed.target,
        run_id: seed.run_id,
        target_label: seed.target_label,
        trace_handle,
    }
}

fn background_tool_trace_handle(
    target: &std::path::Path,
    run_id: &str,
    sink: JobEventSink,
    trace_budget: LiveTraceBudget,
) -> TraceHandle {
    let inner_sink: Arc<dyn TraceSink> = Arc::new(JsonlSink::new(target.to_path_buf(), run_id));
    let broadcast_sink: Arc<dyn TraceSink> =
        Arc::new(StampedTraceSink::new(inner_sink, sink, trace_budget));
    let initial_step_number = next_run_trace_step_number(target, run_id).saturating_sub(1);
    TraceHandle::with_initial_step_number(broadcast_sink, initial_step_number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_run_receipt_records_the_execution_model_not_the_profile_model() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-5.5".to_string());

        let runtime_free = persist_background_tool_run_start(
            &registry,
            &config,
            &workspace,
            "recon:import",
            &serde_json::json!({"tool": "httpx", "path": "recon.jsonl"}),
        )
        .unwrap();
        let runtime_backed = persist_background_tool_run_start(
            &registry,
            &config,
            &workspace,
            "deep-audit:run",
            &serde_json::json!({}),
        )
        .unwrap();

        let free_summary =
            kuzushi_core::load_run_summary(workspace.root(), &runtime_free.run_id).unwrap();
        let backed_summary =
            kuzushi_core::load_run_summary(workspace.root(), &runtime_backed.run_id).unwrap();
        assert_eq!(free_summary.model, None);
        assert_eq!(backed_summary.model.as_deref(), Some("openai:gpt-5.5"));
    }
}
