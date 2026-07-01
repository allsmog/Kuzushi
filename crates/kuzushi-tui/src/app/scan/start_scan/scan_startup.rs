use super::*;

impl ShellApp {
    pub(crate) fn start_scan(&mut self, target: Option<PathBuf>) {
        let Some(request) = self.prepare_scan_start(target) else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        let cancel = ScanCancellation::default();

        self.begin_scan_state(&request, rx, cancel.clone());
        self.spawn_scan_worker(request, tx, cancel);
    }

    fn spawn_scan_worker(
        &self,
        request: ScanStartRequest,
        tx: mpsc::Sender<ScanEvent>,
        cancel: ScanCancellation,
    ) {
        thread::spawn(move || {
            scan_worker(
                request.target_root,
                request.db_path,
                tx,
                cancel,
                request.input,
                request.registry,
                request.config,
                request.thinking_level,
            )
        });
    }

    fn begin_scan_state(
        &mut self,
        request: &ScanStartRequest,
        rx: mpsc::Receiver<ScanEvent>,
        cancel: ScanCancellation,
    ) {
        let run_id = new_run_id("scan");
        self.target = Some(request.target_root.clone());
        self.scan = Some(queued_scan_panel(&request.target_root, &run_id));
        self.scan_rx = Some(rx);
        self.scan_cancel = Some(cancel);
        self.findings.clear();
        self.selected_finding = None;
        self.active_model_override = active_model_override_from_input(&request.input, &self.config);
        self.activity = Some(self.pending_scan_activity(&run_id));
        self.shell_view = self.scan_shell_view();
        self.log_scan_start(&request.target_root);
    }

    fn pending_scan_activity(&self, run_id: &str) -> ActivitySession {
        let mut session = ActivitySession::new(run_id);
        session.seed_from_registry(&self.registry);
        session
    }

    fn scan_shell_view(&self) -> ShellView {
        if self.auto_open_activity {
            ShellView::Activity
        } else {
            ShellView::ModuleRun
        }
    }

    fn log_scan_start(&mut self, target_root: &PathBuf) {
        self.log("scan", format!("starting {}", target_root.display()));
        if self.auto_open_activity {
            self.log(
                "view",
                "opened activity — c cancels run; type `back` to leave (disable: setg ui.auto_open_activity false)",
            );
        }
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Searching,
            "sast:scan",
            format!("scanning {}", target_root.display()),
        ));
    }

    fn prepare_scan_start(&mut self, target: Option<PathBuf>) -> Option<ScanStartRequest> {
        if self.scan.as_ref().is_some_and(|scan| scan.running) {
            self.log("scan", "scan already running");
            return None;
        }
        self.resolve_scan_start_request(target)
    }

    fn resolve_scan_start_request(&mut self, target: Option<PathBuf>) -> Option<ScanStartRequest> {
        let target_path = self.scan_target_path(target);
        let workspace = self.scan_workspace(&target_path)?;
        let input = self.scan_input_or_log()?;
        Some(ScanStartRequest {
            target_root: workspace.root().to_path_buf(),
            db_path: workspace.findings_db_path(),
            input,
            registry: self.registry.clone(),
            config: self.config.clone(),
            thinking_level: self.session_thinking_level.clone(),
        })
    }

    fn scan_target_path(&self, target: Option<PathBuf>) -> PathBuf {
        target
            .or_else(|| self.target.clone())
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

    fn scan_input_or_log(&mut self) -> Option<serde_json::Value> {
        match self.scan_input_from_store() {
            Ok(input) => Some(input),
            Err(error) => {
                self.log("error", error.to_string());
                None
            }
        }
    }

    pub(crate) fn scan_input_from_store(&self) -> Result<serde_json::Value> {
        self.registry.prepare_tool_input(
            "sast:scan",
            serde_json::json!({}),
            Some(&self.option_store),
        )
    }
}

fn queued_scan_panel(target_root: &PathBuf, run_id: &str) -> ScanPanelState {
    ScanPanelState {
        run_id: Some(run_id.to_string()),
        target: target_root.clone(),
        stage: "queued".to_string(),
        findings_count: 0,
        running: true,
        abort_requested: false,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queued_scan_panel_seeds_failure_handoff_run_id() {
        let temp = tempfile::tempdir().unwrap();
        let panel = queued_scan_panel(&temp.path().to_path_buf(), "scan-seeded");

        assert_eq!(panel.run_id.as_deref(), Some("scan-seeded"));
        assert!(panel.running);
    }
}

struct ScanStartRequest {
    target_root: PathBuf,
    db_path: PathBuf,
    input: serde_json::Value,
    registry: ModuleRegistry,
    config: V2Config,
    thinking_level: Option<String>,
}
