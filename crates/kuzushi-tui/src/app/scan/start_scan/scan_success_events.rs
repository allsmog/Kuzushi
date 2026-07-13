use super::*;

#[derive(Clone, Copy)]
enum ScanResultKind {
    Completed,
    Partial,
    Skipped,
    Failed,
}

fn scan_result_run_id(result: &serde_json::Value) -> Option<String> {
    result
        .pointer("/data/runId")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|run_id| !run_id.is_empty())
        .map(ToString::to_string)
}

fn scan_result_findings_count(result: &serde_json::Value) -> usize {
    kuzushi_core::run_artifacts::tool_run_output_findings_count(result)
        .and_then(|count| usize::try_from(count).ok())
        .unwrap_or_default()
}

fn scan_result_message(result: &serde_json::Value, fallback: &str) -> String {
    result
        .get("errors")
        .and_then(serde_json::Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(serde_json::Value::as_str)
        .or_else(|| result.get("summary").and_then(serde_json::Value::as_str))
        .or_else(|| result.get("output").and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|message| !message.is_empty())
        .unwrap_or(fallback)
        .to_string()
}

impl ShellApp {
    #[cfg(test)]
    pub(crate) fn apply_scan_finished(
        &mut self,
        run_id: String,
        findings_count: usize,
    ) -> Vec<ShellEffect> {
        self.apply_scan_result(serde_json::json!({
            "ok": true,
            "status": "completed",
            "summary": "sast:scan completed",
            "data": {
                "runId": run_id,
                "findingsCount": findings_count,
            },
            "warnings": [],
            "errors": [],
        }))
    }

    pub(crate) fn apply_scan_result(&mut self, result: serde_json::Value) -> Vec<ShellEffect> {
        let Some(run_id) = scan_result_run_id(&result).or_else(|| self.active_scan_run_id()) else {
            return self.apply_scan_failed(scan_result_message(
                &result,
                "sast:scan result omitted data.runId",
            ));
        };
        let findings_count = scan_result_findings_count(&result);
        let cost = match kuzushi_core::run_artifacts::tool_run_output_cost_report(&result) {
            Ok(cost) => cost,
            Err(error) => {
                self.report_cost_accounting_error(error);
                kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE
            }
        };
        match kuzushi_core::tool_result_status(&result) {
            kuzushi_core::ToolResultStatus::Completed => {
                self.apply_completed_scan_result(run_id, findings_count, cost, result)
            }
            kuzushi_core::ToolResultStatus::Partial => {
                self.apply_partial_scan_result(run_id, findings_count, cost, result)
            }
            kuzushi_core::ToolResultStatus::Skipped => {
                self.apply_skipped_scan_result(run_id, findings_count, cost, result)
            }
            kuzushi_core::ToolResultStatus::Failed => {
                self.apply_failed_scan_result(run_id, findings_count, cost, result)
            }
        }
    }

    fn apply_completed_scan_result(
        &mut self,
        run_id: String,
        findings_count: usize,
        cost: kuzushi_core::runtime::RuntimeCostReport,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
        self.mark_scan_activity_run_id(&run_id);
        self.record_scan_result_cost(&run_id, cost);
        self.mark_scan_panel_terminal(&run_id, findings_count, "completed", None);
        self.mark_scan_tasks_terminal();
        let target_label = self.scan_target_label();
        let target = self.scan_target_owned();
        vec![ShellEffect::RecordScanRun(ScanRunRecord {
            target,
            run_id,
            target_label,
            outcome: ScanRunOutcome::Complete { result },
        })]
    }

    fn apply_partial_scan_result(
        &mut self,
        run_id: String,
        findings_count: usize,
        cost: kuzushi_core::runtime::RuntimeCostReport,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
        self.mark_scan_activity_run_id(&run_id);
        self.record_scan_result_cost(&run_id, cost);
        let message = scan_result_message(&result, "scan returned a partial result");
        self.mark_scan_panel_terminal(&run_id, findings_count, "partial", Some(message.clone()));
        self.mark_scan_tasks_partial(&message);
        self.set_partial_activity("sast:scan", "usable partial result retained");
        self.set_warn_notice("scan", format!("sast:scan partial: {message}"));
        self.log(
            "scan",
            format!(
                "partial {} with {findings_count} {} — {message}",
                short_fingerprint(&run_id),
                scan_finding_label(findings_count),
            ),
        );
        self.log("result", "partial (scan incomplete) exit_hint=1");
        self.scan_result_artifact_effect(run_id, result, ScanResultKind::Partial)
    }

    fn apply_failed_scan_result(
        &mut self,
        run_id: String,
        findings_count: usize,
        cost: kuzushi_core::runtime::RuntimeCostReport,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
        self.mark_scan_activity_run_id(&run_id);
        self.record_scan_result_cost(&run_id, cost);
        let message = scan_result_message(&result, "scan returned a failed result");
        self.mark_scan_panel_terminal(&run_id, findings_count, "failed", Some(message.clone()));
        self.mark_scan_activity_failed(&message);
        self.set_failed_activity("sast:scan", "scan returned a failed result");
        self.set_error_notice("scan", message.clone());
        self.log(
            "error",
            format!("stage=scan task=sast:scan msg={message:?}"),
        );
        self.log("result", "fail (scan failed) exit_hint=1");
        self.scan_result_artifact_effect(run_id, result, ScanResultKind::Failed)
    }

    fn apply_skipped_scan_result(
        &mut self,
        run_id: String,
        findings_count: usize,
        cost: kuzushi_core::runtime::RuntimeCostReport,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
        self.mark_scan_activity_run_id(&run_id);
        self.record_scan_result_cost(&run_id, cost);
        let message = scan_result_message(&result, "scan reported skipped");
        self.mark_scan_panel_terminal(&run_id, findings_count, "skipped", None);
        self.mark_scan_tasks_skipped();
        self.set_skipped_activity("sast:scan", "scan reported skipped");
        self.set_info_notice("scan", format!("⊘ sast:scan skipped — {message}"));
        self.log(
            "scan",
            format!("skipped {} — {message}", short_fingerprint(&run_id)),
        );
        self.log("result", "skipped (scan did not run) exit_hint=0");
        self.scan_result_artifact_effect(run_id, result, ScanResultKind::Skipped)
    }

    fn active_scan_run_id(&self) -> Option<String> {
        self.scan().and_then(|scan| scan.run_id.clone())
    }

    fn record_scan_result_cost(
        &mut self,
        run_id: &str,
        cost: kuzushi_core::runtime::RuntimeCostReport,
    ) {
        match self.checked_scan_terminal_cost(run_id, cost) {
            Ok(cost) => self.settle_run_cost_report(run_id, cost),
            Err(error) => self.report_cost_accounting_error(error),
        }
    }

    fn scan_result_artifact_effect(
        &self,
        run_id: String,
        result: serde_json::Value,
        kind: ScanResultKind,
    ) -> Vec<ShellEffect> {
        let outcome = match kind {
            ScanResultKind::Completed => ScanRunOutcome::Complete { result },
            ScanResultKind::Partial => ScanRunOutcome::Partial { result },
            ScanResultKind::Skipped => ScanRunOutcome::Skipped { result },
            ScanResultKind::Failed => ScanRunOutcome::FailedResult { result },
        };
        vec![ShellEffect::RecordScanRun(ScanRunRecord {
            target: self.scan_target_owned(),
            run_id,
            target_label: self.scan_target_label(),
            outcome,
        })]
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
        self.seed_devex_phase_fixture_if_requested();
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
        if findings_count == 0 {
            return;
        }
        // `auto_open_viz_page` owns both the pin check and the Activity-deck
        // projection. A finding-producing scan therefore lands on Heatmap in
        // an unpinned Activity view, while a pinned deck remains untouched.
        self.auto_open_viz_page(crate::scene3d::VizPage::Heatmap);
    }

    fn mark_scan_panel_terminal(
        &mut self,
        run_id: &str,
        findings_count: usize,
        status: &str,
        error: Option<String>,
    ) {
        self.set_scan_run_id(run_id.to_string());
        let Some(scan) = self.scan_mut() else {
            return;
        };
        scan.stage = status.to_string();
        scan.findings_count = findings_count;
        scan.running = false;
        scan.abort_requested = false;
        scan.error = error;
        self.set_scan_abort_reason(None);
        self.set_active_model_override(None);
    }

    fn mark_scan_activity_run_id(&mut self, run_id: &str) {
        self.set_activity_run_id(run_id.to_string());
    }

    fn mark_scan_tasks_terminal(&mut self) {
        let Some(session) = self.activity_mut() else {
            return;
        };
        session.mark_incomplete_tasks_after_success(ActivityTerminalContext::Scan);
    }

    fn mark_scan_tasks_partial(&mut self, message: &str) {
        let Some(session) = self.activity_mut() else {
            return;
        };
        session.mark_task_partial("sast:scan", message);
        session.mark_incomplete_tasks_after_failure();
    }

    fn mark_scan_tasks_skipped(&mut self) {
        let Some(session) = self.activity_mut() else {
            return;
        };
        session.mark_task_skipped("sast:scan");
        session.mark_incomplete_tasks_after_skipped();
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

    pub(crate) fn record_scan_run_effect(&mut self, record: ScanRunRecord) -> Vec<ShellEffect> {
        let effects = self.record_scan_run_outcome(record);
        self.invalidate_view_hydration();
        let mut cache = self.workbench_cache().borrow_mut();
        cache.invalidate_run_summaries();
        cache.invalidate_workspace_files();
        effects
    }

    fn record_scan_run_outcome(&mut self, record: ScanRunRecord) -> Vec<ShellEffect> {
        let ScanRunRecord {
            target,
            run_id,
            target_label,
            outcome,
        } = record;
        match split_scan_result_outcome(outcome) {
            Ok((result, kind)) => {
                self.persist_scan_result(target.as_deref(), &run_id, result, kind)
            }
            Err(outcome) => {
                if let Err(error) = record_scan_lifecycle_artifacts(
                    target.as_deref(),
                    &run_id,
                    &target_label,
                    outcome,
                ) {
                    self.report_scan_lifecycle_persistence_failure(&run_id, &error);
                }
                Vec::new()
            }
        }
    }

    fn persist_scan_result(
        &mut self,
        target: Option<&std::path::Path>,
        run_id: &str,
        result: serde_json::Value,
        kind: ScanResultKind,
    ) -> Vec<ShellEffect> {
        let target = target.map(std::path::Path::to_path_buf);
        match try_record_scan_result_artifacts(target.as_deref(), run_id, &result) {
            Ok(()) => scan_result_followup_effects(target, run_id, &result, kind),
            Err(error) => {
                self.report_scan_result_persistence_failure(run_id, &result, &error);
                scan_result_refresh_effects(target, kind)
            }
        }
    }

    fn report_scan_result_persistence_failure(
        &mut self,
        run_id: &str,
        result: &serde_json::Value,
        error: &anyhow::Error,
    ) {
        let status = kuzushi_core::tool_result_status(result);
        let message = format!(
            "sast:scan {} result could not be persisted for {run_id}: {error}",
            scan_status_label(status),
        );
        let findings_count = scan_result_findings_count(result);
        if matches!(
            status,
            kuzushi_core::ToolResultStatus::Completed | kuzushi_core::ToolResultStatus::Partial
        ) {
            self.mark_scan_panel_terminal(run_id, findings_count, "partial", Some(message.clone()));
            self.mark_scan_tasks_partial(&message);
            self.set_partial_activity("sast:scan", "result usable; run artifacts incomplete");
            self.set_warn_notice("artifacts", message.clone());
        } else {
            self.mark_scan_panel_terminal(run_id, findings_count, "failed", Some(message.clone()));
            self.mark_scan_activity_failed(&message);
            self.set_failed_activity("sast:scan", "run artifact finalization failed");
            self.set_error_notice("artifacts", message.clone());
        }
        self.log("error", message);
    }

    fn report_scan_lifecycle_persistence_failure(&mut self, run_id: &str, error: &anyhow::Error) {
        let message =
            format!("sast:scan terminal state could not be persisted for {run_id}: {error}");
        if let Some(scan) = self.scan_mut() {
            scan.stage = "terminal state not persisted".to_string();
            scan.error = Some(message.clone());
        }
        self.set_failed_activity("sast:scan", "run artifact finalization failed");
        self.set_error_notice("artifacts", message.clone());
        self.log("error", message);
    }
}

fn split_scan_result_outcome(
    outcome: ScanRunOutcome,
) -> Result<(serde_json::Value, ScanResultKind), ScanRunOutcome> {
    match outcome {
        ScanRunOutcome::Complete { result } => Ok((result, ScanResultKind::Completed)),
        ScanRunOutcome::Partial { result } => Ok((result, ScanResultKind::Partial)),
        ScanRunOutcome::Skipped { result } => Ok((result, ScanResultKind::Skipped)),
        ScanRunOutcome::FailedResult { result } => Ok((result, ScanResultKind::Failed)),
        outcome @ (ScanRunOutcome::Failed { .. }
        | ScanRunOutcome::Canceled { .. }
        | ScanRunOutcome::Interrupted { .. }) => Err(outcome),
    }
}

fn record_scan_lifecycle_artifacts(
    target: Option<&std::path::Path>,
    run_id: &str,
    target_label: &str,
    outcome: ScanRunOutcome,
) -> anyhow::Result<()> {
    match outcome {
        ScanRunOutcome::Failed { error } => {
            record_scan_failure_artifacts(target, run_id, target_label, &error)
        }
        ScanRunOutcome::Canceled {
            reason,
            findings_count,
        } => record_scan_canceled_artifacts(target, run_id, target_label, &reason, findings_count),
        ScanRunOutcome::Interrupted { reason } => {
            record_scan_interrupted_artifacts(target, run_id, target_label, &reason)
        }
        _ => unreachable!("result-bearing scan outcome was not split before persistence"),
    }
}

fn try_record_scan_result_artifacts(
    target: Option<&std::path::Path>,
    run_id: &str,
    result: &serde_json::Value,
) -> anyhow::Result<()> {
    let target = target.ok_or_else(|| anyhow::anyhow!("scan target snapshot was unavailable"))?;
    kuzushi_core::run_artifacts::try_record_tool_run_complete(
        kuzushi_core::run_artifacts::ToolRunRecord::new(target, run_id, "scan", "sast:scan"),
        result,
    )
}

fn scan_result_followup_effects(
    target: Option<std::path::PathBuf>,
    run_id: &str,
    result: &serde_json::Value,
    kind: ScanResultKind,
) -> Vec<ShellEffect> {
    let mut effects = scan_result_refresh_effects(target, kind);
    if matches!(kind, ScanResultKind::Completed) {
        effects.push(ShellEffect::FinalizeScanCompletion(
            ScanCompletionFinalize {
                run_id: run_id.to_string(),
                findings_count: scan_result_findings_count(result),
            },
        ));
    }
    effects
}

fn scan_result_refresh_effects(
    target: Option<std::path::PathBuf>,
    kind: ScanResultKind,
) -> Vec<ShellEffect> {
    if matches!(kind, ScanResultKind::Skipped) {
        return Vec::new();
    }
    vec![
        ShellEffect::RefreshFindings(FindingsRefresh {
            announce: false,
            filter: None,
        }),
        ShellEffect::HydrateSceneSnapshots(SceneSnapshotsHydration { target }),
    ]
}

fn scan_status_label(status: kuzushi_core::ToolResultStatus) -> &'static str {
    match status {
        kuzushi_core::ToolResultStatus::Completed => "completed",
        kuzushi_core::ToolResultStatus::Partial => "partial",
        kuzushi_core::ToolResultStatus::Skipped => "skipped",
        kuzushi_core::ToolResultStatus::Failed => "failed",
    }
}

fn record_scan_failure_artifacts(
    target: Option<&std::path::Path>,
    run_id: &str,
    target_label: &str,
    error: &str,
) -> anyhow::Result<()> {
    append_trace_step(
        target,
        run_id,
        "refused",
        &short_label(error, 80),
        None,
        None,
    );
    scan_lifecycle_persistence_result([
        (
            "terminal summary",
            write_scan_terminal_summary(target, run_id, target_label, "failed", Some(error), None),
        ),
        (
            "status event",
            append_run_status_event(target, run_id, "sast:scan", "failed", "sast:scan failed"),
        ),
        (
            "failure handoff",
            write_run_failure_handoff(target, run_id, "sast:scan", "failed", error),
        ),
    ])
}

fn record_scan_canceled_artifacts(
    target: Option<&std::path::Path>,
    run_id: &str,
    target_label: &str,
    reason: &str,
    findings_count: Option<usize>,
) -> anyhow::Result<()> {
    append_trace_step(target, run_id, "tool", "scan canceled", None, None);
    scan_lifecycle_persistence_result([
        (
            "terminal summary",
            write_scan_terminal_summary(
                target,
                run_id,
                target_label,
                "canceled",
                Some(reason),
                findings_count,
            ),
        ),
        (
            "status event",
            append_run_status_event(target, run_id, "sast:scan", "canceled", reason),
        ),
    ])
}

fn record_scan_interrupted_artifacts(
    target: Option<&std::path::Path>,
    run_id: &str,
    target_label: &str,
    reason: &str,
) -> anyhow::Result<()> {
    append_trace_step(target, run_id, "refused", "scan interrupted", None, None);
    scan_lifecycle_persistence_result([
        (
            "terminal summary",
            write_scan_terminal_summary(
                target,
                run_id,
                target_label,
                "interrupted",
                Some(reason),
                None,
            ),
        ),
        (
            "status event",
            append_run_status_event(target, run_id, "sast:scan", "interrupted", reason),
        ),
    ])
}

fn write_scan_terminal_summary(
    target: Option<&std::path::Path>,
    run_id: &str,
    target_label: &str,
    status: &str,
    reason: Option<&str>,
    findings_count: Option<usize>,
) -> anyhow::Result<()> {
    let Some(target) = target else { return Ok(()) };
    let seed = kuzushi_core::load_run_summary(target, run_id).unwrap_or_else(|_| {
        kuzushi_core::RunSummary::running(
            run_id,
            "scan",
            Some("sast:scan".to_string()),
            target_label,
        )
    });
    let prior_cost = seed.checked_cost_report()?;
    let trace_cost = kuzushi_core::run_artifacts::trace_cost_report(target, run_id)?;
    let cost = kuzushi_core::run_artifacts::reconcile_terminal_cost_reports(
        prior_cost,
        trace_cost,
        "scan lifecycle terminal",
    )?;
    let seed = seed.with_findings(findings_count.map(|count| count as u64));
    let summary = match status {
        "completed" => seed.complete(),
        "failed" => seed.failed(reason.unwrap_or("scan failed")),
        "canceled" => seed.canceled(reason.unwrap_or("scan canceled")),
        "interrupted" => seed.interrupted(reason.unwrap_or("scan interrupted")),
        _ => seed,
    }
    .with_cost_report(cost);
    kuzushi_core::write_run_summary(target, &summary).map(|_| ())
}

fn scan_lifecycle_persistence_result<const N: usize>(
    results: [(&str, anyhow::Result<()>); N],
) -> anyhow::Result<()> {
    let errors = results
        .into_iter()
        .filter_map(|(artifact, result)| result.err().map(|error| format!("{artifact}: {error}")))
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(errors.join("; "))
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

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{ToolResultStatus, V2Config};

    #[test]
    fn every_scan_terminal_outcome_invalidates_run_summary_cache() {
        for (outcome, status) in result_scan_terminal_outcomes() {
            assert_outcome_refreshes_cache(outcome, status);
        }
        for (outcome, status) in lifecycle_scan_terminal_outcomes() {
            assert_outcome_refreshes_cache(outcome, status);
        }
    }

    #[test]
    fn early_canceled_scan_summary_retains_scan_tool_identity() {
        let temp = tempfile::tempdir().unwrap();
        let run_id = "scan-early-cancel";

        write_scan_terminal_summary(
            Some(temp.path()),
            run_id,
            temp.path().to_str().unwrap(),
            "canceled",
            Some("operator cancel"),
            Some(0),
        )
        .unwrap();

        let summary = kuzushi_core::load_run_summary(temp.path(), run_id).unwrap();
        assert_eq!(summary.status, "canceled");
        assert_eq!(summary.kind, "scan");
        assert_eq!(summary.tool.as_deref(), Some("sast:scan"));
    }

    #[test]
    fn lifecycle_terminal_preserves_seed_cost_when_trace_is_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        let run_id = "scan-seed-cost";
        let seed = kuzushi_core::RunSummary::running(
            run_id,
            "scan",
            Some("sast:scan".to_string()),
            temp.path().display().to_string(),
        )
        .with_cost(Some(0.41));
        kuzushi_core::write_run_summary(temp.path(), &seed).unwrap();

        write_scan_terminal_summary(
            Some(temp.path()),
            run_id,
            temp.path().to_str().unwrap(),
            "failed",
            Some("scanner failed"),
            None,
        )
        .unwrap();

        let summary = kuzushi_core::load_run_summary(temp.path(), run_id).unwrap();
        assert_eq!(summary.cost_usd, Some(0.41));
    }

    fn result_scan_terminal_outcomes() -> [(ScanRunOutcome, &'static str); 4] {
        [
            (
                ScanRunOutcome::Complete {
                    result: result_for_status(ToolResultStatus::Completed),
                },
                "completed",
            ),
            (
                ScanRunOutcome::Partial {
                    result: result_for_status(ToolResultStatus::Partial),
                },
                "partial",
            ),
            (
                ScanRunOutcome::Skipped {
                    result: result_for_status(ToolResultStatus::Skipped),
                },
                "skipped",
            ),
            (
                ScanRunOutcome::FailedResult {
                    result: result_for_status(ToolResultStatus::Failed),
                },
                "failed",
            ),
        ]
    }

    fn lifecycle_scan_terminal_outcomes() -> [(ScanRunOutcome, &'static str); 3] {
        [
            (
                ScanRunOutcome::Failed {
                    error: "scan failed".to_string(),
                },
                "failed",
            ),
            (
                ScanRunOutcome::Canceled {
                    reason: "operator cancel".to_string(),
                    findings_count: Some(1),
                },
                "canceled",
            ),
            (
                ScanRunOutcome::Interrupted {
                    reason: "worker lost".to_string(),
                },
                "interrupted",
            ),
        ]
    }

    fn assert_outcome_refreshes_cache(outcome: ScanRunOutcome, expected_status: &str) {
        let temp = tempfile::tempdir().unwrap();
        let run_id = format!("scan-cache-{expected_status}");
        kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
            kuzushi_core::run_artifacts::ToolRunRecord::new(
                temp.path(),
                &run_id,
                "scan",
                "sast:scan",
            ),
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        append_test_scan_cost(temp.path(), &run_id, 0.125);
        let mut app = ShellApp::new(V2Config::default(), None);
        assert_eq!(
            app.workbench_cache()
                .borrow_mut()
                .run_summary_index(Some(temp.path()), vec![run_id.clone()])[&run_id]
                .status,
            "running"
        );

        let _ = app.record_scan_run_effect(ScanRunRecord {
            target: Some(temp.path().to_path_buf()),
            run_id: run_id.clone(),
            target_label: temp.path().display().to_string(),
            outcome,
        });

        let summaries = app
            .workbench_cache()
            .borrow_mut()
            .run_summary_index(Some(temp.path()), vec![run_id.clone()]);
        assert_eq!(summaries[&run_id].status, expected_status);
        assert_eq!(summaries[&run_id].cost_usd, Some(0.125));
    }

    #[test]
    fn completed_scan_reconciles_trace_cost_into_session_and_activity() {
        let temp = tempfile::tempdir().unwrap();
        let run_id = "scan-trace-cost";
        seed_test_scan_run(temp.path(), run_id);
        append_test_scan_cost(temp.path(), run_id, 0.33);
        let mut app = running_scan_app_at(run_id, temp.path());
        app.begin_run_cost_tracking(run_id, true);

        let effects = app.apply_scan_result(scan_result(run_id, "completed", true, &[]));

        assert_eq!(app.session().session_cost_usd(), 0.33);
        assert_eq!(
            app.activity()
                .unwrap()
                .runtime_cost_report()
                .unwrap()
                .exact_usd(),
            Some(0.33)
        );
        EffectRuntime::execute(&mut app, effects);
        assert_eq!(
            kuzushi_core::load_run_summary(temp.path(), run_id)
                .unwrap()
                .cost_usd,
            Some(0.33)
        );
    }

    #[test]
    fn lifecycle_persistence_failure_is_visible_and_not_reported_as_durable() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join(".kuzushi"), "not a directory").unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        let effects = app.record_scan_run_effect(ScanRunRecord {
            target: Some(temp.path().to_path_buf()),
            run_id: "scan-ledger-failure".to_string(),
            target_label: temp.path().display().to_string(),
            outcome: ScanRunOutcome::Failed {
                error: "scanner failed".to_string(),
            },
        });

        assert!(effects.is_empty());
        assert!(app.log_lines().iter().any(|line| {
            line.prefix == "error" && line.body.contains("terminal state could not be persisted")
        }));
    }

    #[test]
    fn partial_scan_result_stays_partial_and_does_not_finalize() {
        let mut app = running_scan_app("scan-partial");
        let result = scan_result("scan-partial", "partial", true, &["one scanner failed"]);

        let effects = app.apply_scan_result(result.clone());

        assert_scan_terminal_state(&app, "partial", Some("one scanner failed"));
        assert_eq!(
            app.live_activity().map(|activity| activity.phase),
            Some(LiveActivityPhase::Partial)
        );
        assert_result_effect(&effects, ToolResultStatus::Partial, &result);
        assert_no_completion_finalize(&effects);
    }

    #[test]
    fn failed_scan_envelope_stays_failed_and_preserves_errors() {
        let mut app = running_scan_app("scan-failed-result");
        let result = scan_result("scan-failed-result", "failed", false, &["scanner crashed"]);

        let effects = app.apply_scan_result(result.clone());

        assert_scan_terminal_state(&app, "failed", Some("scanner crashed"));
        assert_eq!(
            app.live_activity().map(|activity| activity.phase),
            Some(LiveActivityPhase::Failed)
        );
        assert_result_effect(&effects, ToolResultStatus::Failed, &result);
        assert_no_completion_finalize(&effects);
    }

    #[test]
    fn skipped_scan_result_stays_skipped_and_does_not_finalize() {
        let mut app = running_scan_app("scan-skipped");
        let result = scan_result("scan-skipped", "skipped", true, &[]);

        let effects = app.apply_scan_result(result.clone());

        assert_scan_terminal_state(&app, "skipped", None);
        assert_eq!(
            app.live_activity().map(|activity| activity.phase),
            Some(LiveActivityPhase::Skipped)
        );
        assert_result_effect(&effects, ToolResultStatus::Skipped, &result);
        assert_no_completion_finalize(&effects);
    }

    #[test]
    fn result_without_run_id_uses_the_immutable_active_scan_id() {
        let mut app = running_scan_app("scan-active");
        let mut result = scan_result("ignored", "partial", true, &["degraded"]);
        result["data"].as_object_mut().unwrap().remove("runId");

        let effects = app.apply_scan_result(result);

        let recorded_run_id = effects.iter().find_map(|effect| match effect {
            ShellEffect::RecordScanRun(record) => Some(record.run_id.as_str()),
            _ => None,
        });
        assert_eq!(recorded_run_id, Some("scan-active"));
    }

    #[test]
    fn completed_scan_persistence_collision_becomes_partial_without_false_finalize() {
        let target = tempfile::tempdir().unwrap();
        let runs_root = kuzushi_core::runs_root(target.path());
        std::fs::create_dir_all(runs_root.parent().unwrap()).unwrap();
        std::fs::write(&runs_root, "path collision").unwrap();
        let mut app = running_scan_app_at("scan-persist-failed", target.path());
        let result = scan_result("scan-persist-failed", "completed", true, &[]);

        let effects = app.apply_scan_result(result);
        EffectRuntime::execute(&mut app, effects);

        assert_scan_terminal_state(
            &app,
            "partial",
            app.scan().and_then(|scan| scan.error.as_deref()),
        );
        assert!(app
            .scan()
            .and_then(|scan| scan.error.as_deref())
            .is_some_and(|error| error.contains("could not be persisted")));
        assert_eq!(
            app.live_activity().map(|activity| activity.phase),
            Some(LiveActivityPhase::Partial)
        );
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("pass")));
        assert!(app.log_lines().iter().any(|line| {
            line.prefix == "error"
                && line
                    .body
                    .contains("completed result could not be persisted")
        }));
    }

    fn running_scan_app(run_id: &str) -> ShellApp {
        running_scan_app_at(
            run_id,
            std::path::Path::new("/tmp/kuzushi-scan-status-test"),
        )
    }

    fn running_scan_app_at(run_id: &str, target: &std::path::Path) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_scan_panel(Some(ScanPanelState {
            run_id: Some(run_id.to_string()),
            target: target.to_path_buf(),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        }));
        app.set_activity(Some(ActivitySession::new(run_id)));
        app
    }

    fn scan_result(run_id: &str, status: &str, ok: bool, errors: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "ok": ok,
            "status": status,
            "summary": format!("scan {status}"),
            "data": {
                "runId": run_id,
                "findingsCount": 2,
            },
            "warnings": [],
            "errors": errors,
        })
    }

    fn result_for_status(status: ToolResultStatus) -> serde_json::Value {
        match status {
            ToolResultStatus::Completed => scan_result("run", "completed", true, &[]),
            ToolResultStatus::Partial => scan_result("run", "partial", true, &["degraded"]),
            ToolResultStatus::Skipped => scan_result("run", "skipped", true, &[]),
            ToolResultStatus::Failed => scan_result("run", "failed", false, &["failed"]),
        }
    }

    fn assert_scan_terminal_state(app: &ShellApp, status: &str, error: Option<&str>) {
        let scan = app.scan().expect("scan panel");
        assert_eq!(scan.stage, status);
        assert!(!scan.running);
        assert_eq!(scan.findings_count, 2);
        assert_eq!(scan.error.as_deref(), error);
    }

    fn assert_result_effect(
        effects: &[ShellEffect],
        expected_status: ToolResultStatus,
        expected_result: &serde_json::Value,
    ) {
        let result = effects.iter().find_map(|effect| match effect {
            ShellEffect::RecordScanRun(record) => match &record.outcome {
                ScanRunOutcome::Complete { result }
                | ScanRunOutcome::Partial { result }
                | ScanRunOutcome::Skipped { result }
                | ScanRunOutcome::FailedResult { result } => Some(result),
                _ => None,
            },
            _ => None,
        });
        assert_eq!(result, Some(expected_result));
        assert_eq!(
            result.map(kuzushi_core::tool_result_status),
            Some(expected_status)
        );
    }

    fn assert_no_completion_finalize(effects: &[ShellEffect]) {
        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, ShellEffect::FinalizeScanCompletion(_))));
    }

    fn seed_test_scan_run(target: &std::path::Path, run_id: &str) {
        kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
            kuzushi_core::run_artifacts::ToolRunRecord::new(target, run_id, "scan", "sast:scan"),
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
    }

    fn append_test_scan_cost(target: &std::path::Path, run_id: &str, cost: f64) {
        let step = kuzushi_core::RunTraceStep::new(0, "reasoning", "scan model call")
            .with_call_attempted(true)
            .with_cost_usd(Some(cost))
            .with_model_metadata("openai:gpt-test", "openai", "fnv1a64:scan");
        kuzushi_core::run_artifacts::append_run_trace_step_with_next_number(target, run_id, &step)
            .unwrap();
    }
}
