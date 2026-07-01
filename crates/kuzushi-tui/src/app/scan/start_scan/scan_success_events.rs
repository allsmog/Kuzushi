use super::*;

impl ShellApp {
    pub(crate) fn apply_scan_finished(&mut self, run_id: String, findings_count: usize) {
        self.mark_scan_panel_completed(&run_id, findings_count);
        self.mark_scan_activity_run_id(&run_id);
        self.mark_active_scan_tasks_done();
        let target_label = self.scan_target_label();
        self.record_scan_completion_artifacts(&run_id, findings_count, &target_label);
        self.refresh_findings(false);
        self.log_scan_alias_hint();
        self.log_scan_completion(&run_id, findings_count);
        self.log_scan_result(
            findings_count,
            &crate::ui_view_models::ci_result_findings_summary(&self.findings, findings_count),
        );
        self.set_completed_activity(
            "sast:scan",
            format!("{findings_count} {}", scan_finding_label(findings_count)),
        );
        self.record_scan_task_durations();
        self.notify_scan_completion(findings_count);
        // Findings are refreshed above, so the Activity output can show the
        // actual review list immediately. If the operator is elsewhere, keep
        // the existing heatmap auto-open behavior; while watching Activity,
        // stay in place and switch the output view to findings.
        if findings_count > 0 {
            if let Some(session) = self.activity.as_mut() {
                session.set_deck_page(crate::ActivityDeckPage::Findings);
            }
            if !matches!(self.shell_view, ShellView::Activity) {
                self.auto_open_viz_page(crate::scene3d::VizPage::Heatmap);
            }
        }
    }

    fn mark_scan_panel_completed(&mut self, run_id: &str, findings_count: usize) {
        let Some(scan) = &mut self.scan else {
            return;
        };
        scan.run_id = Some(run_id.to_string());
        scan.stage = "completed".to_string();
        scan.findings_count = findings_count;
        scan.running = false;
        scan.abort_requested = false;
        scan.error = None;
        self.active_model_override = None;
    }

    fn mark_scan_activity_run_id(&mut self, run_id: &str) {
        let Some(session) = self.activity.as_mut() else {
            return;
        };
        session.run_id = run_id.to_string();
    }

    fn mark_active_scan_tasks_done(&mut self) {
        let Some(session) = self.activity.as_mut() else {
            return;
        };
        let now = std::time::Instant::now();
        for row in session.tasks.values_mut() {
            mark_active_scan_task_done(row, now);
        }
    }

    /// Feed the ETA history with every task this scan completed, so the
    /// ambient chip can forecast the next run.
    fn record_scan_task_durations(&mut self) {
        let durations: Vec<(String, u64)> = self
            .activity
            .as_ref()
            .map(completed_task_durations)
            .unwrap_or_default();
        for (task_id, secs) in durations {
            self.task_durations.record_secs(&task_id, secs);
        }
    }

    /// Green completion banner when the scan lands while the operator is
    /// on another view (ambient-progress story).
    fn notify_scan_completion(&mut self, findings_count: usize) {
        if matches!(self.shell_view, ShellView::Activity) {
            return;
        }
        self.set_success_notice(
            "scan",
            format!(
                "✓ scan finished — {findings_count} {} · `findings` to review",
                scan_finding_label(findings_count)
            ),
        );
    }

    fn record_scan_completion_artifacts(
        &self,
        run_id: &str,
        findings_count: usize,
        target_label: &str,
    ) {
        append_trace_step(
            self.target.as_deref(),
            run_id,
            1_000,
            "tool",
            &format!(
                "completed · {findings_count} {}",
                scan_finding_label(findings_count)
            ),
            None,
            None,
        );
        write_run_summary(
            self.target.as_deref(),
            run_id,
            "complete",
            Some(findings_count as u64),
            target_label,
        );
        append_run_status_event(
            self.target.as_deref(),
            run_id,
            "sast:scan",
            "completed",
            format!(
                "sast:scan completed with {findings_count} {}",
                scan_finding_label(findings_count)
            ),
        );
    }

    fn log_scan_completion(&mut self, run_id: &str, findings_count: usize) {
        self.log(
            "scan",
            format!(
                "completed {} with {} {}",
                short_fingerprint(run_id),
                findings_count,
                scan_finding_label(findings_count),
            ),
        );
    }

    fn log_scan_result(&mut self, findings_count: usize, findings_summary: &str) {
        let verdict = if findings_count == 0 { "pass" } else { "fail" };
        let exit_hint = if findings_count == 0 { 0 } else { 1 };
        self.log(
            "result",
            format!("{verdict} ({findings_summary}) exit_hint={exit_hint}"),
        );
    }
}

fn completed_task_durations(session: &crate::app::ActivitySession) -> Vec<(String, u64)> {
    session
        .tasks
        .values()
        .filter_map(|row| {
            let started = row.started_at?;
            let completed = row.completed_at?;
            Some((
                row.task_id.clone(),
                completed.saturating_duration_since(started).as_secs(),
            ))
        })
        .collect()
}

fn mark_active_scan_task_done(row: &mut crate::app::DagTaskRow, now: std::time::Instant) {
    if matches!(row.state, crate::app::DagTaskState::Active) {
        row.state = crate::app::DagTaskState::Done;
        row.completed_at = Some(now);
    }
}

fn scan_finding_label(count: usize) -> &'static str {
    if count == 1 {
        "finding"
    } else {
        "findings"
    }
}
