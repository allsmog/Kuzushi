use super::*;

impl ShellApp {
    pub(crate) fn start_scan(&mut self, target: Option<PathBuf>) {
        let Some(request) = self.prepare_scan_start(target) else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        let cancel = ScanCancellation::default();

        self.target = Some(request.target_root.clone());
        self.scan = Some(ScanPanelState {
            run_id: None,
            target: request.target_root.clone(),
            stage: "queued".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        });
        self.scan_rx = Some(rx);
        self.scan_cancel = Some(cancel.clone());
        self.findings.clear();
        self.selected_finding = None;
        self.shell_view = ShellView::ModuleRun;
        self.log(
            "scan",
            format!("starting {}", request.target_root.display()),
        );
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Searching,
            "sast:scan",
            format!("scanning {}", request.target_root.display()),
        ));

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

    pub(crate) fn scan_options_from_store(&self) -> Result<ScanRunOptions> {
        let input = self.scan_input_from_store()?;
        Ok(ScanRunOptions {
            severity: parse_scan_severity_filter(&input)?,
            tasks: parse_native_scan_tasks(&input)?,
            static_proof_state: None,
            index_static_evidence: false,
        })
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
