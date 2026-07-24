use super::*;

impl ShellApp {
    pub(crate) fn apply_scan_failed(&mut self, error: String) -> Vec<ShellEffect> {
        if let Some(reason) = self.scan_failure_abort_reason() {
            return if reason.records_canceled() {
                self.apply_scan_canceled(&error, reason)
            } else {
                self.apply_scan_interrupted(&error, reason)
            };
        }
        let actionable = with_next_step(
            error,
            "tasks, task block semgrep, or run semgrep:scan {\"binary\":\"/path/to/semgrep\"}",
        );
        let run_id = self.mark_scan_failed(&actionable);
        self.settle_unreported_scan_cost(run_id.as_deref());
        self.mark_scan_activity_failed(&actionable);
        let effects = self.scan_failure_artifact_effect(run_id, &actionable);
        self.log_structured_scan_error(&actionable);
        self.set_error_notice("scan", actionable.clone());
        self.log("result", "fail (scan failed) exit_hint=1");
        self.set_refused_activity("sast:scan", "scan failed");
        effects
    }

    fn scan_failure_abort_reason(&self) -> Option<AbortReason> {
        self.scan_abort_reason().or_else(|| {
            self.scan()
                .is_some_and(|scan| scan.abort_requested)
                .then_some(AbortReason::Operator)
        })
    }

    /// Operator-initiated abort: this "failure" is the cancel the operator
    /// asked for, not a scanner crash. Report it quietly (no red ERROR
    /// notice, no "go block semgrep" remediation), record the run as
    /// interrupted rather than failed, and surface the partial findings that
    /// streamed into the store before the abort.
    fn apply_scan_canceled(&mut self, error: &str, reason: AbortReason) -> Vec<ShellEffect> {
        let run_id = self.scan().and_then(|scan| scan.run_id.clone());
        let retained = run_id
            .as_deref()
            .and_then(|run_id| self.count_store_findings(run_id));
        let summary_line = scan_canceled_summary(retained);
        let run_id = self.mark_scan_canceled(retained).or(run_id);
        self.settle_unreported_scan_cost(run_id.as_deref());
        self.mark_scan_activity_canceled(&summary_line);
        self.log("scan", format!("ended after abort request: {error}"));
        self.log("scan", summary_line);
        self.log("result", "canceled (scan stopped) exit_hint=1");
        self.set_live_activity_state(None);
        let mut effects = vec![ShellEffect::RefreshFindings(FindingsRefresh {
            announce: false,
            filter: None,
        })];
        if let Some(run_id) = run_id {
            effects.push(ShellEffect::RecordScanRun(ScanRunRecord {
                target: self.scan_target_owned(),
                run_id,
                target_label: self.scan_target_label(),
                outcome: ScanRunOutcome::Canceled {
                    reason: format!("{}: {error}", reason.label()),
                    findings_count: retained,
                },
            }));
        }
        effects
    }

    fn apply_scan_interrupted(&mut self, error: &str, reason: AbortReason) -> Vec<ShellEffect> {
        let run_id = self.mark_scan_interrupted(error);
        self.settle_unreported_scan_cost(run_id.as_deref());
        self.mark_scan_activity_failed(error);
        self.set_error_notice(
            "scan",
            format!("scan interrupted by {}: {error}", reason.label()),
        );
        self.log("result", "interrupted (scan did not finish) exit_hint=1");
        self.set_live_activity_state(None);
        run_id
            .map(|run_id| {
                vec![ShellEffect::RecordScanRun(ScanRunRecord {
                    target: self.scan_target_owned(),
                    run_id,
                    target_label: self.scan_target_label(),
                    outcome: ScanRunOutcome::Interrupted {
                        reason: format!("{}: {error}", reason.label()),
                    },
                })]
            })
            .unwrap_or_default()
    }

    fn mark_scan_canceled(&mut self, retained: Option<usize>) -> Option<String> {
        let run_id = self.scan().and_then(|scan| scan.run_id.clone());
        if let Some(scan) = self.scan_mut() {
            scan.stage = "canceled".to_string();
            scan.running = false;
            scan.abort_requested = false;
            scan.error = None;
            if let Some(count) = retained {
                scan.findings_count = count;
            }
        }
        self.set_active_model_override(None);
        self.set_scan_abort_reason(None);
        run_id
    }

    fn mark_scan_interrupted(&mut self, error: &str) -> Option<String> {
        let run_id = self.scan().and_then(|scan| scan.run_id.clone());
        if let Some(scan) = self.scan_mut() {
            scan.stage = "interrupted".to_string();
            scan.running = false;
            scan.abort_requested = false;
            scan.error = Some(error.to_string());
        }
        self.set_scan_abort_reason(None);
        self.set_active_model_override(None);
        run_id
    }

    fn mark_scan_activity_canceled(&mut self, summary_line: &str) {
        if let Some(session) = self.activity_mut() {
            session.mark_active_tasks_canceled();
        }
        let _ = summary_line;
    }

    /// Count the findings currently persisted for the active target — the
    /// same store the RefreshFindings effect reloads — so the cancel message
    /// can report how many partial findings survived the abort.
    fn count_store_findings(&mut self, run_id: &str) -> Option<usize> {
        let target = self.scan_target_owned()?;
        let (_, store) = open_finding_store_for_target_read_only(Some(&target)).ok()?;
        let filter = kuzushi_core::FindingListFilter {
            run_id: vec![run_id.to_string()],
            limit: 0,
            ..Default::default()
        };
        store
            .list_findings_filtered(&filter)
            .ok()
            .map(|report| report.count)
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
        self.set_scan_abort_reason(None);
        self.set_active_model_override(None);
        run_id
    }

    pub(super) fn mark_scan_activity_failed(&mut self, error: &str) {
        if let Some(session) = self.activity_mut() {
            session.mark_incomplete_tasks_after_failure();
        }
        let _ = error;
    }

    fn scan_failure_artifact_effect(
        &self,
        run_id: Option<String>,
        error: &str,
    ) -> Vec<ShellEffect> {
        run_id
            .map(|run_id| {
                ShellEffect::RecordScanRun(ScanRunRecord {
                    target: self.scan_target_owned(),
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

    fn settle_unreported_scan_cost(&mut self, run_id: Option<&str>) {
        let Some(run_id) = run_id else { return };
        match self.checked_scan_terminal_cost(
            run_id,
            kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
        ) {
            Ok(cost) => self.settle_run_cost_report(run_id, cost),
            Err(error) => self.report_cost_accounting_error(error),
        }
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

fn scan_canceled_summary(retained: Option<usize>) -> String {
    match retained {
        Some(0) => "canceled — no findings were recorded before the abort".to_string(),
        Some(count) => format!(
            "canceled — {count} partial finding{} retained · `findings` to browse",
            if count == 1 { "" } else { "s" }
        ),
        None => "canceled — partial findings (if any) remain in the findings store".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{FindingStore, Severity, V2Config};

    fn canceled_scan_panel(target: &std::path::Path, run_id: &str) -> ScanPanelState {
        ScanPanelState {
            run_id: Some(run_id.to_string()),
            target: target.to_path_buf(),
            stage: "abort requested".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: true,
            error: None,
        }
    }

    fn seed_partial_findings(target: &std::path::Path, run_id: &str, count: usize) {
        let workspace = WorkspaceTarget::new(target).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started(run_id, workspace.root(), "running")
            .unwrap();
        for n in 0..count {
            let finding = kuzushi_core::Finding::new_tool(
                "semgrep",
                &format!("rule-{n}"),
                &format!("src/file{n}.ts"),
                n as u32 + 1,
                None,
                Severity::High,
                &format!("partial finding {n}"),
            );
            store.insert_finding(run_id, &finding).unwrap();
        }
    }

    fn seed_scan_run_start(target: &std::path::Path, run_id: &str) {
        kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
            kuzushi_core::run_artifacts::ToolRunRecord::new(target, run_id, "scan", "sast:scan"),
            &serde_json::json!({"runId": run_id}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
    }

    fn assert_quiet_canceled_scan(app: &ShellApp) {
        assert!(app.advisory().notice.is_none());
        assert!(!app
            .log_lines()
            .iter()
            .any(|line| { line.body.contains("task block semgrep") || line.prefix == "error" }));
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.prefix == "scan" && line.body.contains("canceled")));
        let scan = app.scan().expect("scan panel retained");
        assert!(!scan.running);
        assert!(!scan.abort_requested);
        assert_eq!(scan.stage, "canceled");
        assert_eq!(scan.error, None, "cancel is not a scanner error");
    }

    fn assert_canceled_scan_effects(effects: &[ShellEffect]) {
        assert!(effects
            .iter()
            .any(|effect| matches!(effect, ShellEffect::RefreshFindings(_))));
        assert!(effects.iter().any(|effect| matches!(
            effect,
            ShellEffect::RecordScanRun(ScanRunRecord {
                outcome: ScanRunOutcome::Canceled { .. },
                ..
            })
        )));
    }

    #[test]
    fn abort_caused_scan_failure_downgrades_to_quiet_cancel() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(tmp.path().to_path_buf()));
        app.set_scan_panel(Some(canceled_scan_panel(tmp.path(), "scan-canceled")));

        let effects = app.apply_scan_failed("scan cancelled".to_string());

        assert_quiet_canceled_scan(&app);
        assert_canceled_scan_effects(&effects);
    }

    #[test]
    fn abort_caused_scan_failure_records_canceled_run_not_failed() {
        let tmp = tempfile::tempdir().unwrap();
        seed_scan_run_start(tmp.path(), "scan-canceled");
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(tmp.path().to_path_buf()));
        app.set_scan_panel(Some(canceled_scan_panel(tmp.path(), "scan-canceled")));

        let effects = app.apply_scan_failed("scan cancelled".to_string());
        EffectRuntime::execute(&mut app, effects);

        let summary = kuzushi_core::load_run_summary(tmp.path(), "scan-canceled").unwrap();
        assert_eq!(summary.status, "canceled");
        assert_eq!(
            summary.error.as_deref(),
            Some("operator cancel: scan cancelled")
        );
        let failures =
            kuzushi_core::run_artifacts::load_run_failures(tmp.path(), "scan-canceled").unwrap();
        assert_eq!(failures.status, "canceled");
        assert!(failures.failures.is_empty());
    }

    #[test]
    fn abort_caused_scan_failure_surfaces_retained_partial_findings() {
        let tmp = tempfile::tempdir().unwrap();
        seed_scan_run_start(tmp.path(), "scan-canceled");
        seed_partial_findings(tmp.path(), "scan-canceled", 2);
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(tmp.path().to_path_buf()));
        app.set_scan_panel(Some(canceled_scan_panel(tmp.path(), "scan-canceled")));

        let effects = app.apply_scan_failed("scan cancelled".to_string());

        assert!(
            app.log_lines()
                .iter()
                .any(|line| line.body.contains("2 partial findings retained")),
            "cancel must report how many partial findings survived"
        );
        assert_eq!(app.scan().unwrap().findings_count, 2);

        EffectRuntime::execute(&mut app, effects);
        assert_eq!(
            app.findings().len(),
            2,
            "RefreshFindings must load the retained partial findings"
        );
        let summary = kuzushi_core::load_run_summary(tmp.path(), "scan-canceled").unwrap();
        assert_eq!(summary.findings, Some(2));
    }

    #[test]
    fn watchdog_scan_failure_keeps_tui_and_durable_status_interrupted() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "scan-watchdog-interrupted";
        seed_scan_run_start(tmp.path(), run_id);
        let record = kuzushi_core::run_artifacts::ToolRunRecord::new(
            tmp.path(),
            run_id,
            "scan",
            "sast:scan",
        );
        kuzushi_core::run_artifacts::try_record_tool_run_interrupted(record, "scan cancelled")
            .unwrap();
        let before = kuzushi_core::load_run_summary(tmp.path(), run_id).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(tmp.path().to_path_buf()));
        app.set_scan_panel(Some(canceled_scan_panel(tmp.path(), run_id)));
        app.set_scan_abort_reason(Some(AbortReason::Watchdog));

        let effects = app.apply_scan_failed("scan cancelled".to_string());
        EffectRuntime::execute(&mut app, effects);

        let after = kuzushi_core::load_run_summary(tmp.path(), run_id).unwrap();
        assert_eq!(app.scan().unwrap().stage, "interrupted");
        assert_eq!(after.status, "interrupted");
        assert_eq!(after.terminal_result_sha256, before.terminal_result_sha256);
        assert!(!app.log_lines().iter().any(|line| {
            line.body.contains("terminal state could not be persisted")
                || line.body.contains("refusing to rewrite")
        }));
    }

    #[test]
    fn genuine_scan_failure_keeps_error_notice_and_remediation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(tmp.path().to_path_buf()));
        app.set_scan_panel(Some(ScanPanelState {
            run_id: Some("scan-failed".to_string()),
            target: tmp.path().to_path_buf(),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        }));

        let effects = app.apply_scan_failed("semgrep binary missing".to_string());

        let notice = app.advisory().notice.as_ref().expect("error notice kept");
        assert_eq!(notice.severity, crate::NoticeSeverity::Error);
        assert!(notice.message.contains("semgrep binary missing"));
        assert!(notice.message.contains("task block semgrep"));
        assert!(effects
            .iter()
            .any(|effect| matches!(effect, ShellEffect::RecordScanRun(_))));
    }

    #[test]
    fn failed_scan_reconciles_exact_trace_cost_before_terminalizing() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = "scan-failed-cost";
        seed_scan_run_cost(tmp.path(), run_id, 0.27);
        let mut app = running_cost_scan_app(tmp.path(), run_id);

        let effects = app.apply_scan_failed("provider failed".to_string());

        assert_eq!(app.session().session_cost_usd(), 0.27);
        assert_eq!(
            app.activity()
                .unwrap()
                .runtime_cost_report()
                .unwrap()
                .exact_usd(),
            Some(0.27)
        );
        EffectRuntime::execute(&mut app, effects);
        assert_eq!(
            kuzushi_core::load_run_summary(tmp.path(), run_id)
                .unwrap()
                .cost_usd,
            Some(0.27)
        );
    }

    fn seed_scan_run_cost(target: &std::path::Path, run_id: &str, cost: f64) {
        kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
            kuzushi_core::run_artifacts::ToolRunRecord::new(target, run_id, "scan", "sast:scan"),
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let writer =
            kuzushi_core::run_lifecycle::RunItemWriter::open(target, run_id, None).unwrap();
        let report = kuzushi_core::runtime::RuntimeCostReport::known(
            kuzushi_core::runtime::RuntimeCost::from_usd(cost, "scan test").unwrap(),
        );
        let item_id = kuzushi_core::run_lifecycle::RunItemId::new();
        let call_id = kuzushi_core::run_lifecycle::RunCallId::new();
        writer
            .emit_and_flush(test_scan_model_started(item_id).with_call(call_id))
            .unwrap();
        writer
            .emit_and_flush(test_scan_model_failed(item_id, report).with_call(call_id))
            .unwrap();
    }

    fn test_scan_model_started(
        item_id: kuzushi_core::run_lifecycle::RunItemId,
    ) -> kuzushi_core::run_lifecycle::RunItemRecord {
        use kuzushi_core::run_lifecycle::*;
        RunItemRecord::new(
            item_id,
            RunItemSource::Runtime,
            RunItemV1::ModelCallStarted {
                provider: SafeText::operator_visible("openai"),
                model: SafeText::operator_visible("openai:gpt-test"),
                operation_fingerprint: OperationFingerprint::from_bytes(b"scan test"),
            },
        )
    }

    fn test_scan_model_failed(
        item_id: kuzushi_core::run_lifecycle::RunItemId,
        cost: kuzushi_core::runtime::RuntimeCostReport,
    ) -> kuzushi_core::run_lifecycle::RunItemRecord {
        use kuzushi_core::run_lifecycle::*;
        RunItemRecord::new(
            item_id,
            RunItemSource::Runtime,
            RunItemV1::ModelCallFinished {
                provider: SafeText::operator_visible("openai"),
                model: SafeText::operator_visible("openai:gpt-test"),
                status: RunItemStatus::Failed,
                latency_ms: 1,
                usage: ModelUsage {
                    input_tokens: None,
                    output_tokens: None,
                },
                cost,
                error_class: Some(SafeText::operator_visible("provider_error")),
            },
        )
    }

    fn running_cost_scan_app(target: &std::path::Path, run_id: &str) -> ShellApp {
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
        app.begin_run_cost_tracking(run_id, true);
        app
    }

    #[test]
    fn scan_canceled_summary_is_honest_about_counts() {
        assert!(scan_canceled_summary(Some(0)).contains("no findings were recorded"));
        assert!(scan_canceled_summary(Some(1)).contains("1 partial finding retained"));
        assert!(scan_canceled_summary(Some(3)).contains("3 partial findings retained"));
        assert!(scan_canceled_summary(None).contains("if any"));
    }
}
