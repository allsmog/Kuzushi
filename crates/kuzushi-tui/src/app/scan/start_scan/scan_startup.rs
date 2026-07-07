use super::*;

impl ShellApp {
    pub(crate) fn open_guided_scan(&mut self, target: Option<PathBuf>) -> Vec<ShellEffect> {
        if self.scan().is_some_and(|scan| scan.running) {
            self.log("scan", "scan already running");
            return Vec::new();
        }
        let Some(mut effects) = self.guided_scan_target_effects(target) else {
            return Vec::new();
        };
        effects.push(ShellEffect::FinalizeGuidedScanOpen);
        effects
    }

    pub(crate) fn finalize_guided_scan_open_effect(&mut self) {
        self.workbench_cache.borrow_mut().invalidate_map_artifacts();
        let Some(journey) = crate::ui_view_models::journey_model(self) else {
            self.log(
                "journey",
                "no active workspace target; set one with `target <path>` first",
            );
            return;
        };
        self.log(
            "scan",
            "opening guided workflow — review checked tasks, then press Enter to run",
        );
        self.open_phase_picker(journey.current);
    }

    fn guided_scan_target_effects(&mut self, target: Option<PathBuf>) -> Option<Vec<ShellEffect>> {
        let Some(target) = target else {
            if self.current_workspace().is_ok() {
                return Some(Vec::new());
            }
            self.log(
                "scan",
                "no active workspace target; run `target <path>` first, or `scan .` to use cwd",
            );
            return None;
        };
        match WorkspaceTarget::new(&target) {
            Ok(_) => Some(vec![ShellEffect::ActivateTarget(TargetActivation {
                path: target,
                selected_scope: None,
                source: TargetActivationSource::Command,
            })]),
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
        let ticket = self.jobs.start(JobKind::Run, "scan");
        let trace_budget = self.jobs.trace_budget();
        let trace_handle = scan_trace_handle(
            &request.target_root,
            &request.run_id,
            ticket.sink(),
            trace_budget.clone(),
        );
        let cancel = ticket.cancel.clone();

        self.begin_scan_state(&request, cancel.clone());
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

    fn begin_scan_state(&mut self, request: &ScanStartRequest, cancel: ScanCancellation) {
        self.set_target(Some(request.target_root.clone()));
        self.set_scan_panel(Some(queued_scan_panel(
            &request.target_root,
            &request.run_id,
        )));
        self.set_scan_cancel(Some(cancel));
        self.findings_mut().clear();
        *self.selected_finding_mut() = None;
        self.engagement.set_phase(crate::app::WorkflowPhase::Hunt);
        self.set_active_model_override(active_model_override_from_input(
            &request.input,
            self.config(),
        ));
        self.set_activity(Some(self.pending_scan_activity(&request.run_id)));
        self.shell_view = self.scan_shell_view();
        self.log_scan_start(&request.target_root, &request.effective_options);
    }

    fn pending_scan_activity(&self, run_id: &str) -> ActivitySession {
        let mut session = ActivitySession::new(run_id);
        session.seed_from_registry(self.registry());
        session
    }

    fn scan_shell_view(&self) -> ShellView {
        if self.ui().auto_open_activity() {
            ShellView::Activity
        } else {
            ShellView::ModuleRun
        }
    }

    fn log_scan_start(&mut self, target_root: &PathBuf, effective_options: &[EffectiveScanOption]) {
        self.log(
            "phase",
            "崩 hunt (2/4): `scan` is the full-scan action for this phase",
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
        if self.scan().is_some_and(|scan| scan.running) {
            self.log("scan", "scan already running");
            return None;
        }
        self.resolve_scan_start_request(target, explicit_input)
    }

    fn resolve_scan_start_request(
        &mut self,
        target: Option<PathBuf>,
        explicit_input: Option<serde_json::Value>,
    ) -> Option<ScanStartRequest> {
        let target_path = self.scan_target_path(target);
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

    fn scan_target_path(&self, target: Option<PathBuf>) -> PathBuf {
        target
            .or_else(|| self.target_owned())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    fn scan_workspace(&mut self, target_path: &PathBuf) -> Option<WorkspaceTarget> {
        match WorkspaceTarget::new(target_path) {
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
        let ctx = ToolExecutionContext {
            config: self.config(),
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
        };
        self.registry().prepare_tool_input_for_dispatch(
            "sast:scan",
            explicit_input.unwrap_or_else(|| serde_json::json!({})),
            &ctx,
            use_stored_options.then_some(self.option_store()),
        )
    }
}
