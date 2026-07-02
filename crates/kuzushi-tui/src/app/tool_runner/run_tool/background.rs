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
        if self.reject_pending_prompt_mutation(&workspace, &tool_name) {
            return;
        }

        let dispatch = prepare_background_tool_dispatch(
            &self.registry,
            &self.config,
            &workspace,
            &tool_name,
            &input,
        );
        self.launch_prepared_background_tool(
            dispatch,
            workspace,
            tool_name,
            input,
            thinking_level,
            status,
            activity,
        );
        self.open_activity_for_started_background_tool();
    }

    fn launch_prepared_background_tool(
        &mut self,
        dispatch: BackgroundToolDispatch,
        workspace: WorkspaceTarget,
        tool_name: String,
        input: serde_json::Value,
        thinking_level: Option<String>,
        status: &str,
        activity: Option<LiveActivity>,
    ) {
        let model_override = active_model_override_from_input(&input, &dispatch.config);
        BackgroundToolWorkerLaunch::from_dispatch(
            dispatch,
            workspace,
            tool_name,
            input,
            thinking_level,
        )
        .attach_and_start(self, status, activity, model_override);
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

    fn reject_pending_prompt_mutation(
        &mut self,
        workspace: &WorkspaceTarget,
        tool_name: &str,
    ) -> bool {
        let (module_id, verb) = tool_name.split_once(':').unwrap_or((tool_name, "run"));
        match kuzushi_core::latest_prompt_mutation(workspace, module_id, verb) {
            Ok(Some(mutation))
                if mutation.status == kuzushi_core::PromptMutationStatus::Pending =>
            {
                self.focused_module = Some(module_id.to_string());
                self.shell_view = ShellView::PromptsEditor;
                self.log(
                    "prompt",
                    format!(
                        "{tool_name} blocked by pending prompt mutation {}; approve or reject it first",
                        mutation.id
                    ),
                );
                true
            }
            Ok(_) => false,
            Err(error) => {
                self.shell_view = ShellView::PromptsEditor;
                self.log(
                    "error",
                    format!("could not read prompt mutations before {tool_name}: {error}"),
                );
                true
            }
        }
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
                "opened activity — Ctrl+C requests abort; type `back` to leave (disable: setg ui.auto_open_activity false)",
            );
        }
    }

    fn attach_background_tool_run(
        &mut self,
        run: &BackgroundToolRun,
        rx: Receiver<ToolEvent>,
        trace_rx: Receiver<RunTraceStep>,
        cancel: ScanCancellation,
        tool_name: &str,
        status: &str,
        activity: Option<LiveActivity>,
        model_override: Option<String>,
    ) {
        self.target = Some(run.target.clone());
        self.tool_rx = Some(rx);
        self.trace_rx = Some(trace_rx);
        self.activity = Some(ActivitySession::new(run.run_id.clone()));
        self.tool_running = Some(tool_name.to_string());
        self.tool_cancel = Some(cancel);
        self.tool_run_id = Some(run.run_id.clone());
        self.active_model_override = model_override;
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
    cancel: ScanCancellation,
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
        cancel,
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
    cancel: ScanCancellation,
}

struct BackgroundToolWorkerLaunch {
    registry: ModuleRegistry,
    config: V2Config,
    tx: mpsc::Sender<ToolEvent>,
    rx: mpsc::Receiver<ToolEvent>,
    trace_rx: mpsc::Receiver<RunTraceStep>,
    run: BackgroundToolRun,
    cancel: ScanCancellation,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: serde_json::Value,
    thinking_level: Option<String>,
}

impl BackgroundToolWorkerLaunch {
    fn from_dispatch(
        dispatch: BackgroundToolDispatch,
        workspace: WorkspaceTarget,
        tool_name: String,
        input: serde_json::Value,
        thinking_level: Option<String>,
    ) -> Self {
        let BackgroundToolDispatch {
            registry,
            config,
            tx,
            rx,
            trace_rx,
            run,
            cancel,
        } = dispatch;
        Self {
            registry,
            config,
            tx,
            rx,
            trace_rx,
            run,
            cancel,
            workspace,
            tool_name,
            input,
            thinking_level,
        }
    }

    fn attach_and_start(
        self,
        app: &mut ShellApp,
        status: &str,
        activity: Option<LiveActivity>,
        model_override: Option<String>,
    ) {
        self.attach(app, status, activity, model_override).start();
    }

    fn attach(
        self,
        app: &mut ShellApp,
        status: &str,
        activity: Option<LiveActivity>,
        model_override: Option<String>,
    ) -> BackgroundToolWorkerStart {
        let rx = self.rx;
        let trace_rx = self.trace_rx;
        let start = BackgroundToolWorkerStart {
            registry: self.registry,
            config: self.config,
            tx: self.tx,
            run: self.run,
            cancel: self.cancel,
            workspace: self.workspace,
            tool_name: self.tool_name,
            input: self.input,
            thinking_level: self.thinking_level,
        };
        app.attach_background_tool_run(
            &start.run,
            rx,
            trace_rx,
            start.cancel.clone(),
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
    tx: mpsc::Sender<ToolEvent>,
    run: BackgroundToolRun,
    cancel: ScanCancellation,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: serde_json::Value,
    thinking_level: Option<String>,
}

impl BackgroundToolWorkerStart {
    fn start(self) {
        start_prepared_background_worker(
            self.registry,
            self.config,
            self.tx,
            self.run,
            self.cancel,
            self.workspace,
            self.tool_name,
            self.input,
            self.thinking_level,
        );
    }
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
    let cancel = ScanCancellation::default();
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
        cancel,
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
    cancel: ScanCancellation,
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
            cancel,
        )
    });
}
