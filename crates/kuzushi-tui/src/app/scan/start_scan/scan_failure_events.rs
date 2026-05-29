use super::*;

impl ShellApp {
    pub(crate) fn apply_scan_failed(&mut self, error: String) {
        let actionable = with_next_step(
            error,
            "tasks, task block semgrep, or run semgrep:scan {\"binary\":\"/path/to/semgrep\"}",
        );
        let run_id = self.mark_scan_failed(&actionable);
        self.mark_scan_activity_failed(&actionable);
        if let Some(run_id) = &run_id {
            self.write_scan_failure_artifacts(run_id, &actionable);
        }
        self.log_structured_scan_error(&actionable);
        self.set_error_notice("scan", actionable);
        self.log("result", "fail (scan failed) exit_hint=1");
        self.set_refused_activity("sast:scan", "scan failed");
    }

    fn mark_scan_failed(&mut self, error: &str) -> Option<String> {
        let run_id = self.scan.as_ref().and_then(|scan| scan.run_id.clone());
        let Some(scan) = &mut self.scan else {
            return run_id;
        };
        scan.stage = "failed".to_string();
        scan.running = false;
        scan.abort_requested = false;
        scan.error = Some(error.to_string());
        run_id
    }

    fn mark_scan_activity_failed(&mut self, error: &str) {
        if let Some(session) = self.activity.as_mut() {
            let now = std::time::Instant::now();
            for row in session.tasks.values_mut() {
                if matches!(row.state, crate::app::DagTaskState::Active) {
                    row.state = crate::app::DagTaskState::Failing;
                    row.completed_at = Some(now);
                    row.severity = Some("danger".to_string());
                    row.last_label = "scan failed".to_string();
                }
            }
            session.apply_step(
                kuzushi_core::RunTraceStep::new(0, "refused", short_label(error, 80))
                    .with_module_id("scan")
                    .with_severity("danger"),
            );
        }
    }

    fn write_scan_failure_artifacts(&self, run_id: &str, error: &str) {
        append_trace_step(
            self.target.as_deref(),
            run_id,
            1_000,
            "refused",
            &short_label(error, 80),
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
        append_run_status_event(
            self.target.as_deref(),
            run_id,
            "sast:scan",
            "failed",
            "sast:scan failed",
        );
        write_run_failure_handoff(self.target.as_deref(), run_id, "sast:scan", "failed", error);
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
