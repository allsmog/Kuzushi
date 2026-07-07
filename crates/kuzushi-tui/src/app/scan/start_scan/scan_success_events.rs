use super::*;

impl ShellApp {
    #[cfg(test)]
    pub(crate) fn apply_scan_finished(
        &mut self,
        run_id: String,
        findings_count: usize,
    ) -> Vec<ShellEffect> {
        self.apply_scan_finished_with_cost(run_id, findings_count, None)
    }

    pub(crate) fn apply_scan_finished_with_cost(
        &mut self,
        run_id: String,
        findings_count: usize,
        cost_usd: Option<f64>,
    ) -> Vec<ShellEffect> {
        if let Some(cost_usd) = cost_usd {
            self.record_cost(cost_usd);
        }
        self.mark_scan_panel_completed(&run_id, findings_count);
        self.mark_scan_activity_run_id(&run_id);
        self.mark_scan_tasks_terminal();
        let target_label = self.scan_target_label();
        let target = self.target_owned();
        vec![
            ShellEffect::RecordScanRun(ScanRunRecord {
                target: target.clone(),
                run_id: run_id.clone(),
                target_label,
                outcome: ScanRunOutcome::Complete { findings_count },
            }),
            ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None,
            }),
            ShellEffect::HydrateSceneSnapshots(SceneSnapshotsHydration { target }),
            ShellEffect::FinalizeScanCompletion(ScanCompletionFinalize {
                run_id,
                findings_count,
            }),
        ]
    }

    pub(crate) fn finalize_scan_completion_effect(&mut self, finalize: ScanCompletionFinalize) {
        let run_id = finalize.run_id;
        let findings_count = finalize.findings_count;
        self.update_workflow_phase_after_scan(findings_count);
        self.log_scan_alias_hint();
        self.log_scan_completion(&run_id, findings_count);
        self.log_scan_result(
            findings_count,
            &crate::ui_view_models::ci_result_findings_summary(self.findings(), findings_count),
        );
        self.set_completed_activity(
            "sast:scan",
            format!("{findings_count} {}", scan_finding_label(findings_count)),
        );
        self.record_scan_task_durations();
        self.notify_scan_completion(findings_count);
        self.maybe_open_scan_findings_output(findings_count);
    }

    fn update_workflow_phase_after_scan(&mut self, findings_count: usize) {
        if findings_count > 0 {
            self.engagement.clear_phase();
            return;
        }
        if self
            .engagement
            .current_phase()
            .is_none_or(|phase| phase <= crate::app::WorkflowPhase::Hunt)
        {
            self.engagement.set_phase(crate::app::WorkflowPhase::Hunt);
        }
    }

    fn maybe_open_scan_findings_output(&mut self, findings_count: usize) {
        // Findings are refreshed above. If the operator allows viz auto-open,
        // the Activity output can switch to the review list when it has not
        // been manually pinned; otherwise leave their page alone.
        if findings_count == 0 {
            return;
        }
        self.maybe_switch_activity_deck_to_findings();
        if !matches!(self.shell_view(), ShellView::Activity) {
            self.auto_open_viz_page(crate::scene3d::VizPage::Heatmap);
        }
    }

    fn maybe_switch_activity_deck_to_findings(&mut self) {
        if !self.ui().auto_open_viz() {
            return;
        }
        if self.activity().is_some() && self.router.activity().can_auto_switch_deck() {
            self.router
                .activity_mut()
                .set_deck_page(crate::ActivityDeckPage::Findings);
        }
    }

    fn mark_scan_panel_completed(&mut self, run_id: &str, findings_count: usize) {
        let Some(scan) = self.scan_mut() else {
            return;
        };
        scan.run_id = Some(run_id.to_string());
        scan.stage = "completed".to_string();
        scan.findings_count = findings_count;
        scan.running = false;
        scan.abort_requested = false;
        scan.error = None;
        self.set_active_model_override(None);
    }

    fn mark_scan_activity_run_id(&mut self, run_id: &str) {
        let Some(session) = self.activity_mut() else {
            return;
        };
        session.run_id = run_id.to_string();
    }

    fn mark_scan_tasks_terminal(&mut self) {
        let Some(session) = self.activity_mut() else {
            return;
        };
        session.mark_incomplete_tasks_after_success(ActivityTerminalContext::Scan);
    }

    /// Feed the ETA history with every task this scan completed, so the
    /// ambient chip can forecast the next run.
    fn record_scan_task_durations(&mut self) {
        let durations: Vec<(String, u64)> = self
            .activity()
            .map(completed_task_durations)
            .unwrap_or_default();
        for (task_id, secs) in durations {
            self.record_task_duration_secs(&task_id, secs);
        }
    }

    /// Green completion banner when the scan lands while the operator is
    /// on another view (ambient-progress story).
    fn notify_scan_completion(&mut self, findings_count: usize) {
        if matches!(self.shell_view(), ShellView::Activity) {
            return;
        }
        self.set_success_notice(
            "scan",
            format!(
                "✓ scan finished — {findings_count} {} · {}",
                scan_finding_label(findings_count),
                scan_completion_next_step(findings_count)
            ),
        );
    }

    fn log_scan_completion(&mut self, run_id: &str, findings_count: usize) {
        self.log(
            "scan",
            format!(
                "completed {} with {} {} · {}",
                short_fingerprint(run_id),
                findings_count,
                scan_finding_label(findings_count),
                scan_completion_next_step(findings_count)
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

    pub(crate) fn record_scan_run_effect(&self, record: ScanRunRecord) {
        match record.outcome {
            ScanRunOutcome::Complete { findings_count } => record_scan_completion_artifacts(
                record.target.as_deref(),
                &record.run_id,
                findings_count,
                &record.target_label,
            ),
            ScanRunOutcome::Failed { error } => record_scan_failure_artifacts(
                record.target.as_deref(),
                &record.run_id,
                &record.target_label,
                &error,
            ),
        }
    }
}

fn record_scan_completion_artifacts(
    target: Option<&std::path::Path>,
    run_id: &str,
    findings_count: usize,
    target_label: &str,
) {
    append_trace_step(
        target,
        run_id,
        "tool",
        &format!(
            "completed · {findings_count} {}",
            scan_finding_label(findings_count)
        ),
        None,
        None,
    );
    write_run_summary(
        target,
        run_id,
        "complete",
        Some(findings_count as u64),
        target_label,
    );
    append_run_status_event(
        target,
        run_id,
        "sast:scan",
        "completed",
        format!(
            "sast:scan completed with {findings_count} {}",
            scan_finding_label(findings_count)
        ),
    );
}

fn record_scan_failure_artifacts(
    target: Option<&std::path::Path>,
    run_id: &str,
    target_label: &str,
    error: &str,
) {
    append_trace_step(
        target,
        run_id,
        "refused",
        &short_label(error, 80),
        None,
        None,
    );
    write_run_summary(target, run_id, "failed", None, target_label);
    append_run_status_event(target, run_id, "sast:scan", "failed", "sast:scan failed");
    write_run_failure_handoff(target, run_id, "sast:scan", "failed", error);
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

fn scan_finding_label(count: usize) -> &'static str {
    if count == 1 {
        "finding"
    } else {
        "findings"
    }
}

fn scan_completion_next_step(findings_count: usize) -> &'static str {
    if findings_count == 0 {
        "崩 hunt remains active · `options sast:scan` to tune or `scan` to rerun"
    } else {
        "next: 作 confirm · `findings` to browse or `next` to triage/verify"
    }
}
