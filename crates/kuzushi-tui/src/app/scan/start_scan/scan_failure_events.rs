use super::*;

impl ShellApp {
    pub(crate) fn apply_scan_failed(&mut self, error: String) -> Vec<ShellEffect> {
        let actionable = with_next_step(
            error,
            "tasks, task block semgrep, or run semgrep:scan {\"binary\":\"/path/to/semgrep\"}",
        );
        let run_id = self.mark_scan_failed(&actionable);
        self.mark_scan_activity_failed(&actionable);
        let effects = self.scan_failure_artifact_effect(run_id, &actionable);
        self.log_structured_scan_error(&actionable);
        self.set_error_notice("scan", actionable.clone());
        self.log("result", "fail (scan failed) exit_hint=1");
        self.set_refused_activity("sast:scan", "scan failed");
        effects
    }

    fn mark_scan_failed(&mut self, error: &str) -> Option<String> {
        let run_id = self.scan().and_then(|scan| scan.run_id.clone());
        let Some(scan) = self.scan_mut() else {
            return run_id;
        };
        scan.stage = "failed".to_string();
        scan.running = false;
        scan.abort_requested = false;
        scan.error = Some(error.to_string());
        self.set_active_model_override(None);
        run_id
    }

    fn mark_scan_activity_failed(&mut self, error: &str) {
        if let Some(session) = self.activity_mut() {
            session.mark_incomplete_tasks_after_failure();
            session.apply_step(
                // 320 keeps the full remedy available to the Activity feed (which
                // wraps error rows); the on-disk trace artifact keeps its own cap.
                kuzushi_core::RunTraceStep::new(0, "refused", short_label(error, 320))
                    .with_module_id("scan")
                    .with_severity("danger"),
            );
        }
    }

    fn scan_failure_artifact_effect(
        &self,
        run_id: Option<String>,
        error: &str,
    ) -> Vec<ShellEffect> {
        run_id
            .map(|run_id| {
                ShellEffect::RecordScanRun(ScanRunRecord {
                    target: self.target_owned(),
                    run_id,
                    target_label: self.scan_target_label(),
                    outcome: ScanRunOutcome::Failed {
                        error: error.to_string(),
                    },
                })
            })
            .into_iter()
            .collect()
    }

    fn log_structured_scan_error(&mut self, error: &str) {
        self.log(
            "error",
            format!("stage=scan task=sast:scan msg={}", quoted_log_value(error)),
        );
    }
}

fn quoted_log_value(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}
