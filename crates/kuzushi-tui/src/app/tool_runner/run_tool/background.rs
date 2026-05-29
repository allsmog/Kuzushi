use super::*;

impl ShellApp {
    pub(crate) fn start_background_tool(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
    ) {
        self.start_background_tool_with_activity(
            tool_name,
            input,
            workspace,
            status,
            thinking_level,
            None,
        );
    }

    pub(crate) fn start_background_tool_with_activity(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
        activity: Option<LiveActivity>,
    ) {
        if self.reject_background_tool_overlap(&tool_name) {
            return;
        }

        let dispatch = prepare_background_tool_dispatch(
            &self.registry,
            &self.config,
            &workspace,
            &tool_name,
            &input,
        );
        let BackgroundToolDispatch {
            registry,
            config,
            tx,
            rx,
            trace_rx,
            run,
        } = dispatch;
        self.attach_background_tool_run(&run, rx, trace_rx, &tool_name, status, activity);
        start_prepared_background_worker(
            registry,
            config,
            tx,
            run,
            workspace,
            tool_name,
            input,
            thinking_level,
        );

        self.open_activity_for_started_background_tool();
    }

    fn reject_background_tool_overlap(&mut self, tool_name: &str) -> bool {
        let Some(active) = self.tool_running.as_deref() else {
            return false;
        };
        self.log(
            "tool",
            format!("{active} is still running; wait for its result before starting {tool_name}"),
        );
        true
    }

    fn open_activity_for_started_background_tool(&mut self) {
        // Auto-open AFTER the worker thread spawns. Earlier, the flip happened
        // before the worker existed, so a fast dispatch error could strand the
        // operator on an empty Activity view. Flipping after thread::spawn
        // guarantees the run is in flight before the view becomes visible.
        if self.auto_open_activity {
            self.shell_view = ShellView::Activity;
            self.log(
                "view",
                "opened activity — Esc/back to leave (disable: setg ui.auto_open_activity false)",
            );
        }
    }

    fn attach_background_tool_run(
        &mut self,
        run: &BackgroundToolRun,
        rx: Receiver<ToolEvent>,
        trace_rx: Receiver<RunTraceStep>,
        tool_name: &str,
        status: &str,
        activity: Option<LiveActivity>,
    ) {
        self.target = Some(run.target.clone());
        self.tool_rx = Some(rx);
        self.trace_rx = Some(trace_rx);
        self.activity = Some(ActivitySession::new(run.run_id.clone()));
        self.tool_running = Some(tool_name.to_string());
        self.tool_run_id = Some(run.run_id.clone());
        self.tool_abort_requested = false;
        self.log(
            "tool",
            format!(
                "running {tool_name} in background; {status} under {} · run {}",
                run.target_label, run.run_id
            ),
        );
        self.set_live_activity(
            activity.unwrap_or_else(|| live_activity_for_tool(tool_name, status)),
        );
    }
}

fn start_prepared_background_worker(
    registry: ModuleRegistry,
    config: V2Config,
    tx: mpsc::Sender<ToolEvent>,
    run: BackgroundToolRun,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: serde_json::Value,
    thinking_level: Option<String>,
) {
    spawn_background_tool_worker(
        registry,
        config,
        workspace,
        tool_name,
        input,
        run.run_id,
        thinking_level,
        tx,
        run.trace_handle,
    );
}

struct BackgroundToolRun {
    target: PathBuf,
    run_id: String,
    target_label: String,
    trace_handle: TraceHandle,
}

struct BackgroundToolDispatch {
    registry: ModuleRegistry,
    config: V2Config,
    tx: mpsc::Sender<ToolEvent>,
    rx: mpsc::Receiver<ToolEvent>,
    trace_rx: mpsc::Receiver<RunTraceStep>,
    run: BackgroundToolRun,
}

fn prepare_background_tool_dispatch(
    registry: &ModuleRegistry,
    config: &V2Config,
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: &serde_json::Value,
) -> BackgroundToolDispatch {
    let registry = registry.clone();
    let config = config.clone();
    let (tx, rx) = mpsc::channel();
    let (trace_tx, trace_rx) = mpsc::channel::<RunTraceStep>();
    let loaded_modules = registry.loaded_module_specifiers();
    let run = prepare_background_tool_run(
        workspace,
        tool_name,
        input,
        &config,
        loaded_modules,
        trace_tx,
    );
    BackgroundToolDispatch {
        registry,
        config,
        tx,
        rx,
        trace_rx,
        run,
    }
}

fn prepare_background_tool_run(
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: &serde_json::Value,
    config: &V2Config,
    loaded_modules: Vec<String>,
    trace_tx: std::sync::mpsc::Sender<RunTraceStep>,
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
    let trace_handle = background_tool_trace_handle(&target, &run_id, trace_tx);
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
    trace_tx: std::sync::mpsc::Sender<RunTraceStep>,
) -> TraceHandle {
    let inner_sink: Arc<dyn TraceSink> = Arc::new(JsonlSink::new(target.to_path_buf(), run_id));
    let broadcast_sink: Arc<dyn TraceSink> = Arc::new(BroadcastSink::new(inner_sink, trace_tx));
    let initial_step_number = next_run_trace_step_number(target, run_id).saturating_sub(1);
    TraceHandle::with_initial_step_number(broadcast_sink, initial_step_number)
}

fn spawn_background_tool_worker(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: serde_json::Value,
    run_id: String,
    thinking_level: Option<String>,
    tx: std::sync::mpsc::Sender<ToolEvent>,
    trace_handle: TraceHandle,
) {
    thread::spawn(move || {
        background_tool_worker(
            registry,
            config,
            workspace,
            tool_name,
            input,
            run_id,
            thinking_level,
            tx,
            Some(trace_handle),
        )
    });
}
