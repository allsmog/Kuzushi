use super::*;

impl ShellApp {
    pub(crate) fn open_guided_scan(&mut self, target: Option<PathBuf>) -> Vec<ShellEffect> {
        if self.scan_start_blocked() {
            return Vec::new();
        }
        let Some(mut effects) = self.guided_scan_target_effects(target) else {
            return Vec::new();
        };
        effects.push(ShellEffect::FinalizeGuidedScanOpen);
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
        self.begin_guided_scan_questions();
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
            Ok(_) => Some(self.request_target_activation(TargetActivation {
                path: target,
                selected_scope: None,
                source: TargetActivationSource::Command,
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
        let trace_budget = self.jobs().trace_budget();
        let trace_handle = scan_trace_handle(
            &request.target_root,
            &request.run_id,
            ticket.sink(),
            trace_budget.clone(),
        );
        let cancel = ticket.cancel.clone();

        self.begin_run_cost_tracking(&request.run_id, runtime_backed);
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
        self.set_scan_abort_reason(None);
        self.set_findings(Vec::new());
        *self.selected_finding_mut() = None;
        self.engagement.set_phase(crate::app::WorkflowPhase::Scan);
        self.set_active_model_override(active_model_override_from_input(
            &request.input,
            self.config(),
        ));
        self.set_activity(Some(self.pending_scan_activity(&request.run_id)));
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

    fn pending_scan_activity(&self, run_id: &str) -> ActivitySession {
        let mut session = ActivitySession::for_phase(run_id, crate::app::WorkflowPhase::Scan);
        session.seed_from_registry(self.registry());
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
            "崩 scan (2/5): `scan` is the discovery action for this phase",
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
                "scan needs an explicit target; use `scan .` to consent to cwd",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_scan_activity_captures_scan_as_its_launch_phase() {
        let app = ShellApp::new(V2Config::default(), None);

        let session = app.pending_scan_activity("scan-origin");

        assert_eq!(session.origin_phase, Some(crate::app::WorkflowPhase::Scan));
    }

    #[test]
    fn scan_workspace_initializes_policy_before_request_state() {
        let target = tempfile::tempdir().unwrap();

        let workspace = initialized_scan_workspace(&target.path().to_path_buf()).unwrap();

        assert!(workspace.root().join(".kuzushi/.gitignore").is_file());
        assert!(workspace.state_dir().is_dir());
    }
}
