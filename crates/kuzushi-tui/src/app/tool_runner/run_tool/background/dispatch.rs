use super::*;
use std::path::PathBuf;

pub(super) struct BackgroundToolRun {
    pub(super) target: PathBuf,
    pub(super) run_id: String,
    pub(super) target_label: String,
    pub(super) trace_handle: TraceHandle,
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
    input: serde_json::Value,
    thinking_level: Option<String>,
}

impl BackgroundToolWorkerLaunch {
    pub(super) fn from_dispatch(
        dispatch: BackgroundToolDispatch,
        workspace: WorkspaceTarget,
        tool_name: String,
        input: serde_json::Value,
        thinking_level: Option<String>,
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
    input: serde_json::Value,
    thinking_level: Option<String>,
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
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: &serde_json::Value,
    ticket: JobTicket,
    trace_budget: LiveTraceBudget,
) -> BackgroundToolDispatch {
    let registry = registry.clone();
    let config = config.clone();
    let loaded_modules = registry.loaded_module_specifiers();
    let run = prepare_background_tool_run(
        workspace,
        tool_name,
        input,
        &config,
        loaded_modules,
        ticket.sink(),
        trace_budget.clone(),
    );
    BackgroundToolDispatch {
        registry,
        config,
        run,
        ticket,
    }
}

fn prepare_background_tool_run(
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: &serde_json::Value,
    config: &V2Config,
    loaded_modules: Vec<String>,
    sink: JobEventSink,
    trace_budget: LiveTraceBudget,
) -> BackgroundToolRun {
    let target = workspace.root().to_path_buf();
    let run_id = new_run_id("tool");
    let target_label = target.display().to_string();
    let record =
        kuzushi_core::run_artifacts::ToolRunRecord::new(&target, &run_id, "tool", tool_name);
    kuzushi_core::run_artifacts::record_tool_run_started_with_reproducibility(
        record,
        input,
        config.model.clone(),
        config_hash(config).ok(),
        loaded_modules,
    );
    let trace_handle = background_tool_trace_handle(&target, &run_id, sink, trace_budget);
    BackgroundToolRun {
        target,
        run_id,
        target_label,
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
