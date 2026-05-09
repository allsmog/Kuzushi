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
        // Mark every Active row as Failing so the dashboard reflects the
        // scan-wide failure visually. We do NOT emit a synthetic
        // `scan:run` row here because the per-scanner rows already show
        // the failure; an extra row would just clutter the DAG pane.
        // Push one feed event with no module_id so it lands without
        // creating a new task entry.
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
            // No verb -> apply_step's `else if let Some(verb)` branch is
            // skipped, so no task row is minted; the event still lands
            // in the feed. `module_id = "scan"` swaps the bare
            // `[refused]` tag for the more semantic `[scan]`. The label
            // surfaces a short version of the actionable error so the
            // operator can glance at the feed and see *why* the scan
            // failed without scrolling to the transcript.
            session.apply_step(
                kuzushi_core::RunTraceStep::new(0, "refused", short_label(&actionable, 80))
                    .with_module_id("scan")
                    .with_severity("danger"),
            );
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
