use super::*;

impl ShellApp {
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
}
