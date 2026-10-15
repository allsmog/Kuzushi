use super::*;

impl ShellApp {
    pub(crate) fn open_guided_scan(&mut self, target: Option<PathBuf>) -> Vec<ShellEffect> {
        if self.scan_start_blocked() {
            return Vec::new();
        }
        let activates_target = target.is_some();
        let Some(mut effects) = self.guided_scan_target_effects(target) else {
            return Vec::new();
        };
        if !activates_target {
            effects.push(ShellEffect::FinalizeGuidedScanOpen);
        }
        effects
    }

    pub(crate) fn finalize_guided_scan_open_effect(&mut self) {
        self.workbench_cache()
            .borrow_mut()
            .invalidate_map_artifacts();
        if self.target().is_none() {
            self.log(
                "journey",
                "no active workspace target; set one with `target <path>` first",
            );
            return;
        }
        self.engagement.clear_guided_scan();
        self.open_setup();
        self.log(
            "full",
            "review Setup, then approve Map and a finite Scan plan before work starts",
        );
    }

    fn guided_scan_target_effects(&mut self, target: Option<PathBuf>) -> Option<Vec<ShellEffect>> {
        let Some(target) = target else {
            if self.current_workspace().is_ok() {
                return Some(Vec::new());
            }
            self.log(
                "full",
                "no active workspace target; choose one first, or use `full .` to select cwd explicitly",
            );
            return None;
        };
        match WorkspaceTarget::new(&target) {
            Ok(_) => Some(self.request_target_activation(TargetActivation {
                path: target,
                selected_scope: None,
                source: TargetActivationSource::GuidedFull,
            })),
            Err(error) => {
                self.log(
                    "error",
                    format!("invalid target {}: {error}", target.display()),
                );
                None
            }
        }
    }

    pub(crate) fn reduce_scan_start(
        &mut self,
        target: Option<PathBuf>,
        explicit_input: Option<serde_json::Value>,
    ) -> Vec<ShellEffect> {
        vec![ShellEffect::PrepareScan(ScanStartPreparation {
            target,
            explicit_input,
        })]
    }

    pub(crate) fn start_prepared_scan(&mut self, request: ScanStartRequest) {
        let runtime_backed =
            request
                .registry
                .tool_wants_runtime("sast:scan", &request.input, &request.config);
        if self.reject_runtime_launch_while_budget_halted(runtime_backed, "scan") {
            return;
        }
        if self.scan_start_blocked() {
            return;
        }
        let Some(ticket) = self.try_start_exclusive_job(JobKind::Run, "scan") else {
            return;
        };
        let attempt_id = kuzushi_core::run_lifecycle::RunAttemptId::new();
        let task_id = kuzushi_core::run_lifecycle::RunTaskId::new();
        let trace_handle = match prepare_scan_launch(&request, &ticket, Some(attempt_id), task_id) {
            Ok(trace) => trace,
            Err(error) => {
                ticket.fail(format!("could not start scan: {error:#}"));
                ticket.complete();
                return;
            }
        };
        let cancel = ticket.cancel.clone();

        self.begin_run_cost_tracking(&request.run_id, runtime_backed);
        self.begin_scan_state(&request, cancel.clone(), attempt_id);
        self.spawn_scan_worker(request, ticket, trace_handle, cancel);
    }

    fn spawn_scan_worker(
        &mut self,
        request: ScanStartRequest,
        ticket: JobTicket,
        trace_handle: TraceHandle,
        cancel: ScanCancellation,
    ) {
        let generation = ticket.generation();
        let watchdog_cancel = cancel.clone();
        let handle = spawn_job_worker("scan", ticket, move |sink, cancel| {
            scan_worker(
                request.target_root,
                request.db_path,
                sink,
                cancel,
                request.input,
                request.registry,
                request.config,
                request.thinking_level,
                trace_handle,
            )
        });
        self.register_worker_handle_with_watchdog("scan", generation, handle, watchdog_cancel);
    }

    pub(crate) fn prepare_scan_start_effect(
        &mut self,
        prepare: ScanStartPreparation,
    ) -> Vec<ShellEffect> {
        self.prepare_scan_start(prepare.target, prepare.explicit_input)
            .map(|request| vec![ShellEffect::StartScan(request)])
            .unwrap_or_default()
    }

    fn begin_scan_state(
        &mut self,
        request: &ScanStartRequest,
        cancel: ScanCancellation,
        attempt_id: kuzushi_core::run_lifecycle::RunAttemptId,
    ) {
        self.set_target(Some(request.target_root.clone()));
        self.set_scan_panel(Some(queued_scan_panel(
            &request.target_root,
            &request.run_id,
        )));
        self.set_scan_cancel(Some(cancel));
        self.set_scan_abort_reason(None);
        self.set_findings(Vec::new());
        *self.selected_finding_mut() = None;
        self.engagement.set_phase(crate::app::WorkflowPhase::Scan);
        self.set_active_model_override(active_model_override_from_input(
            &request.input,
            self.config(),
        ));
        self.set_activity(Some(
            self.pending_scan_activity(&request.run_id, attempt_id),
        ));
        self.record_session_event(kuzushi_core::session_transcript::SessionEvent::RunStarted {
            run_id: request.run_id.clone(),
            tool_name: "sast:scan".to_string(),
        });
        self.set_shell_view(self.scan_shell_view());
        if self.shell_view() == ShellView::Activity {
            self.set_input_mode(InputMode::Navigate);
        }
        self.log_scan_start(&request.target_root, &request.effective_options);
    }

    fn pending_scan_activity(
        &self,
        run_id: &str,
        attempt_id: kuzushi_core::run_lifecycle::RunAttemptId,
    ) -> ActivitySession {
        let session = ActivitySession::for_phase(run_id, crate::app::WorkflowPhase::Scan)
            .with_phase_attempt_id(attempt_id);
        self.capture_run_focus_origin(session)
    }

    fn scan_shell_view(&self) -> ShellView {
        if self.ui().auto_open_activity() {
            ShellView::Activity
        } else {
            ShellView::Workbench
        }
    }

    fn log_scan_start(&mut self, target_root: &PathBuf, effective_options: &[EffectiveScanOption]) {
        self.log(
            "phase",
            "Scan (2/5): `scan` is the discovery action for this phase",
        );
        self.log("scan", format!("starting {}", target_root.display()));
        self.log(
            "scan",
            "setup: `tasks` chooses scanners · `options sast:scan` tunes inputs · Ctrl+G opens commands",
        );
        self.log("scan", scan_options_log_message(effective_options));
        if self.ui().auto_open_activity() {
            self.log(
                "view",
                "opened activity — Ctrl+C requests abort; type `back` to leave (disable: setg ui.auto_open_activity false)",
            );
        }
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Searching,
            "sast:scan",
            format!("scanning {}", target_root.display()),
        ));
    }

    fn prepare_scan_start(
        &mut self,
        target: Option<PathBuf>,
        explicit_input: Option<serde_json::Value>,
    ) -> Option<ScanStartRequest> {
        if self.scan_start_blocked() {
            return None;
        }
        self.resolve_scan_start_request(target, explicit_input)
    }

    fn scan_start_blocked(&mut self) -> bool {
        if !self.has_running_work() {
            return false;
        }
        self.log(
            "scan",
            "scan start blocked — finish or cancel the active work, then retry",
        );
        true
    }

    fn resolve_scan_start_request(
        &mut self,
        target: Option<PathBuf>,
        explicit_input: Option<serde_json::Value>,
    ) -> Option<ScanStartRequest> {
        let Some(target_path) = self.scan_target_path(target) else {
            self.log(
                "error",
                "scan execution needs an explicit target; use `kuzushi scan <target>` for scripts",
            );
            return None;
        };
        let workspace = self.scan_workspace(&target_path)?;
        let run_id = new_run_id("scan");
        let effective_options = if explicit_input.is_some() {
            Vec::new()
        } else {
            effective_scan_options(self.registry(), self.option_store())
        };
        let input =
            scan_input_with_run_id(self.scan_input_or_log(explicit_input, &workspace)?, &run_id);
        Some(ScanStartRequest {
            run_id,
            target_root: workspace.root().to_path_buf(),
            db_path: workspace.findings_db_path(),
            input,
            effective_options,
            registry: self.registry().clone(),
            config: self.config().clone(),
            thinking_level: self.session_thinking_level_owned(),
        })
    }

    fn scan_target_path(&self, target: Option<PathBuf>) -> Option<PathBuf> {
        target.or_else(|| self.target_owned())
    }

    fn scan_workspace(&mut self, target_path: &PathBuf) -> Option<WorkspaceTarget> {
        match initialized_scan_workspace(target_path) {
            Ok(workspace) => Some(workspace),
            Err(error) => {
                self.log("error", error.to_string());
                None
            }
        }
    }

    fn scan_input_or_log(
        &mut self,
        explicit_input: Option<serde_json::Value>,
        workspace: &WorkspaceTarget,
    ) -> Option<serde_json::Value> {
        match self.scan_input_from_explicit(explicit_input, workspace) {
            Ok(input) => Some(input),
            Err(error) => {
                self.log("error", error.to_string());
                None
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn scan_input_from_store(&self) -> Result<serde_json::Value> {
        let workspace = self.current_workspace()?;
        self.scan_input_from_explicit(None, &workspace)
    }

    fn scan_input_from_explicit(
        &self,
        explicit_input: Option<serde_json::Value>,
        workspace: &WorkspaceTarget,
    ) -> Result<serde_json::Value> {
        let use_stored_options = explicit_input.is_none();
        let input = explicit_input.unwrap_or_else(|| serde_json::json!({}));
        let input = force_shell_discovery_only_sast_input("sast:scan", input);
        anyhow::ensure!(input.is_object(), "shell scan input must be a JSON object");
        let ctx = ToolExecutionContext {
            config: self.config(),
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        self.registry().prepare_tool_input_for_dispatch(
            "sast:scan",
            input,
            &ctx,
            use_stored_options.then_some(self.option_store()),
        )
    }
}

fn initialized_scan_workspace(target: &PathBuf) -> Result<WorkspaceTarget> {
    let workspace = WorkspaceTarget::new(target)?;
    workspace.ensure_state_dir()?;
    Ok(workspace)
}

fn prepare_scan_launch(
    request: &ScanStartRequest,
    ticket: &JobTicket,
    attempt_id: Option<kuzushi_core::run_lifecycle::RunAttemptId>,
    task_id: kuzushi_core::run_lifecycle::RunTaskId,
) -> Result<TraceHandle> {
    persist_scan_run_start(request)?;
    let trace = scan_trace_handle(
        &request.target_root,
        &request.run_id,
        ticket.sink(),
        attempt_id,
        task_id,
    );
    trace.map_err(|error| fail_persisted_scan_launch(request, error))
}

fn fail_persisted_scan_launch(request: &ScanStartRequest, error: anyhow::Error) -> anyhow::Error {
    let message = format!("typed scan lifecycle could not start: {error:#}");
    let record = kuzushi_core::run_artifacts::ToolRunRecord::new(
        &request.target_root,
        &request.run_id,
        "scan",
        "sast:scan",
    );
    match kuzushi_core::run_artifacts::try_record_tool_run_failed(record, &message) {
        Ok(()) => anyhow::anyhow!(message),
        Err(finalization) => {
            let fallback = persist_unobservable_scan_failure(request, &message);
            anyhow::anyhow!(
                "{message}; typed finalization reported: {finalization:#}; metadata fallback: {fallback}"
            )
        }
    }
}

fn persist_unobservable_scan_failure(request: &ScanStartRequest, message: &str) -> String {
    let metadata = kuzushi_core::run_artifacts::run_artifact_path(
        &request.target_root,
        &request.run_id,
        "run.json",
    );
    let result = std::fs::read_to_string(metadata)
        .map_err(anyhow::Error::from)
        .and_then(|value| {
            serde_json::from_str::<kuzushi_core::RunSummary>(&value).map_err(Into::into)
        })
        .map(|summary| summary.failed(message))
        .and_then(|summary| kuzushi_core::write_run_summary(&request.target_root, &summary));
    match result {
        Ok(_) => "recorded failed run without lifecycle fidelity".to_string(),
        Err(error) => format!("failed ({error:#})"),
    }
}

fn persist_scan_run_start(request: &ScanStartRequest) -> Result<()> {
    let record = kuzushi_core::run_artifacts::ToolRunRecord::new(
        &request.target_root,
        &request.run_id,
        "scan",
        "sast:scan",
    );
    kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &request.input,
        kuzushi_core::tool_execution_model("sast:scan", &request.input, &request.config),
        kuzushi_core::config_hash(&request.config).ok(),
        request.registry.loaded_module_specifiers(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_scan_activity_captures_scan_as_its_launch_phase() {
        let app = ShellApp::new(V2Config::default(), None);
        let attempt_id = kuzushi_core::run_lifecycle::RunAttemptId::new();

        let session = app.pending_scan_activity("scan-origin", attempt_id);

        assert_eq!(session.origin_phase, Some(crate::app::WorkflowPhase::Scan));
        assert_eq!(session.phase_attempt_id, Some(attempt_id));
    }

    #[test]
    fn scan_workspace_initializes_policy_before_request_state() {
        let target = tempfile::tempdir().unwrap();

        let workspace = initialized_scan_workspace(&target.path().to_path_buf()).unwrap();

        assert!(workspace.root().join(".kuzushi/.gitignore").is_file());
        assert!(workspace.state_dir().is_dir());
    }

    #[test]
    fn scan_launch_persists_exact_input_and_execution_model_before_dispatch() {
        let target = tempfile::tempdir().unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-test".to_string());
        let input = serde_json::json!({
            "runId": "scan-launch",
            "triage": true,
            "model": "openai:gpt-test"
        });
        let request = ScanStartRequest {
            run_id: "scan-launch".to_string(),
            target_root: target.path().to_path_buf(),
            db_path: target.path().join("findings.sqlite"),
            input: input.clone(),
            effective_options: Vec::new(),
            registry: ModuleRegistry::with_v2_builtins(),
            config,
            thinking_level: None,
        };

        persist_scan_run_start(&request).unwrap();

        let summary = kuzushi_core::load_run_summary(target.path(), "scan-launch").unwrap();
        assert_eq!(summary.status, "running");
        assert_eq!(summary.tool.as_deref(), Some("sast:scan"));
        assert_eq!(summary.model.as_deref(), Some("openai:gpt-test"));
        let kuzushi_core::RunArtifactRead::Ready { value, .. } =
            kuzushi_core::read_run_artifact_text(target.path(), "scan-launch", "input.json")
        else {
            panic!("canonical scan input must be readable before dispatch");
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&value).unwrap(),
            input
        );
    }

    #[test]
    fn failed_scan_start_does_not_emit_a_typed_stream_without_run_metadata() {
        let target = tempfile::tempdir().unwrap();
        let request = test_scan_start_request(target.path(), "scan-start-failed");
        let metadata = kuzushi_core::run_artifacts::run_artifact_path(
            target.path(),
            "scan-start-failed",
            "run.json",
        );
        std::fs::create_dir_all(&metadata).unwrap();
        let mut jobs = JobHub::default();
        let ticket = jobs.start(JobKind::Run, "scan");

        let launched = prepare_scan_launch(
            &request,
            &ticket,
            Some(kuzushi_core::run_lifecycle::RunAttemptId::new()),
            kuzushi_core::run_lifecycle::RunTaskId::new(),
        );

        assert!(launched.is_err());
        assert!(!kuzushi_core::run_dir(target.path(), "scan-start-failed")
            .join("items.jsonl")
            .exists());
        assert!(jobs.drain(8).is_empty());
    }

    #[test]
    fn trace_initialization_failure_terminalizes_seeded_run_without_activating_scan() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "scan-trace-start-failed";
        let request = test_scan_start_request(target.path(), run_id);
        let items_lock =
            kuzushi_core::run_artifacts::run_artifact_path(target.path(), run_id, "items.lock");
        std::fs::create_dir_all(&items_lock).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        app.start_prepared_scan(request);

        std::fs::remove_dir(items_lock).unwrap();
        let summary = kuzushi_core::load_run_summary(target.path(), run_id).unwrap();
        assert_eq!(summary.status, "failed");
        assert!(summary
            .error
            .as_deref()
            .is_some_and(|error| error.contains("typed scan lifecycle could not start")));
        assert!(app.scan().is_none());
        assert!(app.activity().is_none());
    }

    fn test_scan_start_request(target: &std::path::Path, run_id: &str) -> ScanStartRequest {
        ScanStartRequest {
            run_id: run_id.to_string(),
            target_root: target.to_path_buf(),
            db_path: target.join("findings.sqlite"),
            input: serde_json::json!({"runId": run_id}),
            effective_options: Vec::new(),
            registry: ModuleRegistry::with_v2_builtins(),
            config: V2Config::default(),
            thinking_level: None,
        }
    }
}
