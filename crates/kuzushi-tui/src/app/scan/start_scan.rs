use super::prelude::*;
use super::*;

impl ShellApp {
    pub(crate) fn start_scan(&mut self, target: Option<PathBuf>) {
        if self.scan.as_ref().is_some_and(|scan| scan.running) {
            self.log("scan", "scan already running");
            return;
        }

        let target_path = target
            .or_else(|| self.target.clone())
            .unwrap_or_else(|| PathBuf::from("."));
        let workspace = match WorkspaceTarget::new(&target_path) {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let scan_options = match self.scan_options_from_store() {
            Ok(options) => options,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let target_root = workspace.root().to_path_buf();
        let db_path = workspace.findings_db_path();
        let (tx, rx) = mpsc::channel();
        let cancel = ScanCancellation::default();

        self.target = Some(target_root.clone());
        self.scan = Some(ScanPanelState {
            run_id: None,
            target: target_root.clone(),
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
        self.log("scan", format!("starting {}", target_root.display()));

        thread::spawn(move || scan_worker(target_root, db_path, tx, cancel, scan_options));
    }

    pub(crate) fn scan_options_from_store(&self) -> Result<ScanRunOptions> {
        let input = self.registry.prepare_tool_input(
            "sast:scan",
            serde_json::json!({}),
            Some(&self.option_store),
        )?;
        Ok(ScanRunOptions {
            severity: parse_scan_severity_filter(&input)?,
            tasks: parse_native_scan_tasks(&input)?,
            static_proof_state: None,
            index_static_evidence: false,
        })
    }

    pub(crate) fn apply_scan_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started { run_id, target } => self.apply_scan_started(run_id, target),
            ScanEvent::Stage(stage) => self.apply_scan_stage(stage),
            ScanEvent::FindingStored {
                fingerprint,
                severity,
                title,
            } => self.apply_scan_finding_stored(fingerprint, severity, title),
            ScanEvent::Finished {
                run_id,
                findings_count,
            } => self.apply_scan_finished(run_id, findings_count),
            ScanEvent::Failed { error } => self.apply_scan_failed(error),
            ScanEvent::Cancelled { run_id } => self.apply_scan_cancelled(run_id),
        }
    }

    pub(crate) fn apply_scan_started(&mut self, run_id: String, target: PathBuf) {
        if let Some(scan) = &mut self.scan {
            scan.run_id = Some(run_id.clone());
            scan.target = target;
            scan.stage = "starting scan".to_string();
            scan.abort_requested = false;
        }
        self.log("scan", format!("run {}", short_fingerprint(&run_id)));
    }

    pub(crate) fn apply_scan_stage(&mut self, stage: String) {
        if let Some(scan) = &mut self.scan {
            scan.stage = stage.clone();
        }
        self.append_scan_stage_trace(&stage);
        self.log("scan", stage);
    }

    pub(crate) fn append_scan_stage_trace(&self, stage: &str) {
        let Some(run_id) = self.scan.as_ref().and_then(|scan| scan.run_id.as_ref()) else {
            return;
        };
        let step_index = self.log.iter().filter(|line| line.prefix == "scan").count() + 1;
        append_trace_step(
            self.target.as_deref(),
            run_id,
            step_index,
            "tool",
            &short_label(stage, 80),
            None,
            None,
        );
    }

    pub(crate) fn apply_scan_finding_stored(
        &mut self,
        fingerprint: String,
        severity: Severity,
        title: String,
    ) {
        if let Some(scan) = &mut self.scan {
            scan.findings_count += 1;
        }
        self.log(
            "finding",
            format!(
                "{} {} {}",
                short_fingerprint(&fingerprint),
                severity.as_str(),
                truncate_ascii(&title, 72)
            ),
        );
    }

    pub(crate) fn apply_scan_finished(&mut self, run_id: String, findings_count: usize) {
        if let Some(scan) = &mut self.scan {
            scan.run_id = Some(run_id.clone());
            scan.stage = "completed".to_string();
            scan.findings_count = findings_count;
            scan.running = false;
            scan.abort_requested = false;
            scan.error = None;
        }
        let target_label = self.scan_target_label();
        append_trace_step(
            self.target.as_deref(),
            &run_id,
            1_000,
            "tool",
            &format!("completed · {findings_count} finding(s)"),
            None,
            None,
        );
        write_run_summary(
            self.target.as_deref(),
            &run_id,
            "complete",
            Some(findings_count as u64),
            &target_label,
        );
        self.refresh_findings(false);
        self.log_scan_alias_hint();
        self.log(
            "scan",
            format!(
                "completed {} with {} finding(s)",
                short_fingerprint(&run_id),
                findings_count
            ),
        );
    }

    pub(crate) fn apply_scan_failed(&mut self, error: String) {
        let actionable = with_next_step(
            error,
            "tasks, task block semgrep, or run semgrep:scan {\"binary\":\"/path/to/semgrep\"}",
        );
        let run_id = self.scan.as_ref().and_then(|scan| scan.run_id.clone());
        if let Some(scan) = &mut self.scan {
            scan.stage = "failed".to_string();
            scan.running = false;
            scan.abort_requested = false;
            scan.error = Some(actionable.clone());
        }
        if let Some(run_id) = &run_id {
            append_trace_step(
                self.target.as_deref(),
                run_id,
                1_000,
                "refused",
                &short_label(&actionable, 80),
                None,
                None,
            );
            write_run_summary(
                self.target.as_deref(),
                run_id,
                "failed",
                None,
                &self.scan_target_label(),
            );
        }
        self.log("error", actionable);
    }

    pub(crate) fn apply_scan_cancelled(&mut self, run_id: String) {
        if let Some(scan) = &mut self.scan {
            scan.run_id = Some(run_id.clone());
            scan.stage = "cancelled".to_string();
            scan.running = false;
            scan.abort_requested = false;
            scan.error = None;
        }
        append_trace_step(
            self.target.as_deref(),
            &run_id,
            1_000,
            "refused",
            "cancelled",
            None,
            None,
        );
        write_run_summary(
            self.target.as_deref(),
            &run_id,
            "paused",
            None,
            &self.scan_target_label(),
        );
        self.log("scan", format!("cancelled {}", short_fingerprint(&run_id)));
    }

    pub(crate) fn scan_target_label(&self) -> String {
        self.target
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| ".".to_string())
    }

    pub(crate) fn log_scan_alias_hint(&mut self) {
        if let Some((alias, finding)) = sorted_finding_aliases(&self.findings).into_iter().next() {
            self.log(
                "scan",
                format!(
                    "top alias {alias} -> {} ({})",
                    short_fingerprint(&finding.fingerprint),
                    truncate_ascii(&finding.title, 64)
                ),
            );
        }
    }
}
