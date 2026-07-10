use super::*;
use kuzushi_core::run_artifacts::{
    load_run_summary, output_with_run_fallback_context, FailureToLlmContext,
};
use std::path::{Path, PathBuf};

struct ToolEventState {
    abort_reason: Option<AbortReason>,
    run_id: Option<String>,
    target: Option<PathBuf>,
}

impl ShellApp {
    pub(crate) fn apply_tool_event(&mut self, event: ToolEvent) -> Vec<ShellEffect> {
        let state = self.take_tool_event_state();
        match event {
            ToolEvent::Finished { tool_name, result } => {
                self.apply_finished_tool_event(state, tool_name, result)
            }
            ToolEvent::Failed { tool_name, error } => {
                self.apply_failed_tool_event(state, tool_name, error)
            }
            ToolEvent::Refused { tool_name, error } => {
                self.apply_refused_tool_event(state, tool_name, error)
            }
        }
    }

    fn take_tool_event_state(&mut self) -> ToolEventState {
        let state = ToolEventState {
            abort_reason: self.tool_abort_reason(),
            run_id: self.take_active_tool_run_id(),
            target: self.target_owned(),
        };
        self.finish_tool_run();
        state
    }

    fn apply_finished_tool_event(
        &mut self,
        state: ToolEventState,
        tool_name: String,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
        let skipped = tool_result_is_skipped(&result);
        if state.abort_reason.is_some() {
            self.log(
                "tool",
                format!("{tool_name} completed after abort request; applying completed result"),
            );
        }
        let mut effects = vec![tool_run_record_effect(
            &state,
            &tool_name,
            ToolRunRecordOutcome::Complete {
                result: result.clone(),
            },
        )];
        effects.extend(self.apply_tool_result_state(&tool_name, &result));
        self.finish_completed_tool_ui(&tool_name, state.abort_reason.is_some(), skipped);
        effects.extend(self.finished_tool_continuation(&tool_name, state.abort_reason.is_none()));
        effects
    }

    fn finish_completed_tool_ui(&mut self, tool_name: &str, abort_requested: bool, skipped: bool) {
        self.set_completed_activity(
            tool_name.to_string(),
            if skipped {
                "tool skipped"
            } else {
                "tool result applied"
            },
        );
        self.mark_tool_activity_complete(tool_name, skipped);
        self.record_tool_duration_and_notify(tool_name, abort_requested, skipped);
        self.auto_open_viz_for_tool(tool_name);
    }

    fn finished_tool_continuation(
        &mut self,
        tool_name: &str,
        allow_continuation: bool,
    ) -> Vec<ShellEffect> {
        if !allow_continuation {
            self.log(
                "planning",
                "automatic continuation paused after cancel request",
            );
            return Vec::new();
        }
        let mut effects = self.advance_chain_after_tool(tool_name);
        effects.extend(self.advance_planning_queue_after_tool(tool_name));
        effects
    }

    /// When a tool that produces a visualizable artifact completes, switch to
    /// its gallery page (gated on `auto_open_viz`). Runs before chain/queue
    /// advance so a follow-up tool's Activity view correctly supersedes it. The
    /// snapshot cache ran inside `apply_tool_result` above, so we can check
    /// whether it actually produced data — a zero-flow hunt or empty chain run
    /// shouldn't yank the operator to a "run the tool" empty page.
    fn auto_open_viz_for_tool(&mut self, tool_name: &str) {
        if tool_name == "threat-model:build" {
            self.auto_open_workbench_dfd();
            return;
        }
        if let Some(page) = viz_page_for_tool(tool_name) {
            if self.viz_page_has_content(page) {
                self.auto_open_viz_page(page);
            }
        }
    }

    /// Resolve a completed tool's Activity DAG row to `Done` when its producer
    /// returned without emitting a terminal step (e.g. a scanner that exits
    /// early because its binary isn't installed). Guarded so tools that already
    /// reported done don't get a duplicate feed line.
    fn mark_tool_activity_complete(&mut self, tool_name: &str, skipped: bool) {
        if let Some(session) = self.activity_mut() {
            if skipped {
                session.mark_task_skipped(tool_name);
            } else {
                session.mark_task_done(tool_name);
            }
            session.mark_incomplete_tasks_after_success(ActivityTerminalContext::Run);
        }
    }

    /// Feed the ETA history and — when the operator is on another view —
    /// raise the completion banner so background work announces itself
    /// instead of finishing silently (ambient-progress story).
    fn record_tool_duration_and_notify(
        &mut self,
        tool_name: &str,
        completed_after_cancel: bool,
        skipped: bool,
    ) {
        let Some(secs) = self.completed_tool_secs(tool_name) else {
            return;
        };
        self.record_task_duration_secs(tool_name, secs);
        if matches!(self.shell_view(), ShellView::Activity) {
            return;
        }
        self.set_success_notice(
            "run",
            tool_completion_notice(tool_name, secs, completed_after_cancel, skipped),
        );
    }

    /// Wall-clock for the finished tool: its DAG row when the run traced
    /// one, otherwise the whole session (single-tool runs).
    fn completed_tool_secs(&self, tool_name: &str) -> Option<u64> {
        let session = self.activity()?;
        let row_secs = session.tasks.get(tool_name).and_then(|row| {
            let started = row.started_at?;
            let completed = row.completed_at?;
            Some(completed.saturating_duration_since(started).as_secs())
        });
        Some(row_secs.unwrap_or_else(|| session.started_at.elapsed().as_secs()))
    }

    fn apply_failed_tool_event(
        &mut self,
        state: ToolEventState,
        tool_name: String,
        error: String,
    ) -> Vec<ShellEffect> {
        if let Some(reason) = state.abort_reason {
            return self.apply_aborted_tool_event(state, tool_name, error, reason);
        }
        let mut effects = vec![tool_run_record_effect(
            &state,
            &tool_name,
            ToolRunRecordOutcome::Failed {
                error: error.clone(),
            },
        )];
        effects.extend(self.tool_result_refresh_effects(&tool_name));
        self.record_failed_tool_spent_cost(&state);
        self.mark_tool_activity_failed(&tool_name, &error);
        self.log_tool_failure(
            &tool_name,
            with_next_step(error.clone(), "tools, options <tool>, or model <n>"),
            false,
        );
        self.set_refused_activity(
            tool_name.clone(),
            "tool failed before producing a usable result",
        );
        self.abort_pending_chain(&tool_name);
        if self.engagement.running_tool_is(&tool_name) {
            // Dependency-aware fall-through: skip only the tasks that depended
            // on this one; keep running the independent rest of the queue.
            effects.extend(self.fail_planning_task(&tool_name, &error));
        }
        effects
    }

    fn apply_aborted_tool_event(
        &mut self,
        state: ToolEventState,
        tool_name: String,
        error: String,
        reason: AbortReason,
    ) -> Vec<ShellEffect> {
        self.record_failed_tool_spent_cost(&state);
        self.abort_pending_chain(&tool_name);
        if reason.records_canceled() {
            if let Some(session) = self.activity_mut() {
                session.mark_active_tasks_canceled();
            }
            self.set_completed_activity(tool_name.clone(), "canceled");
            self.log(
                "tool",
                format!("{tool_name} canceled ({}) — {error}", reason.label()),
            );
            return vec![tool_run_record_effect(
                &state,
                &tool_name,
                ToolRunRecordOutcome::Canceled {
                    reason: format!("{}: {error}", reason.label()),
                },
            )];
        }

        self.mark_tool_activity_failed(&tool_name, &error);
        self.set_error_notice(
            "tool",
            format!("{tool_name} interrupted by {}: {error}", reason.label()),
        );
        vec![tool_run_record_effect(
            &state,
            &tool_name,
            ToolRunRecordOutcome::Interrupted {
                reason: format!("{}: {error}", reason.label()),
            },
        )]
    }

    fn apply_refused_tool_event(
        &mut self,
        state: ToolEventState,
        tool_name: String,
        error: String,
    ) -> Vec<ShellEffect> {
        self.record_failed_tool_spent_cost(&state);
        if let Some(session) = self.activity_mut() {
            session.mark_task_blocked(&tool_name, &error);
        }
        self.set_refused_activity(tool_name.clone(), "blocked by autonomy posture");
        self.set_warn_notice("autonomy", error.clone());
        self.abort_pending_chain(&tool_name);
        if self.engagement.running_tool_is(&tool_name) {
            self.engagement.pause_planning_queue();
        }
        vec![tool_run_record_effect(
            &state,
            &tool_name,
            ToolRunRecordOutcome::Refused { reason: error },
        )]
    }

    /// A failed tool reports only an error string, so unlike the success path
    /// there is no result JSON carrying `costUsd`. The per-LLM-call spend has
    /// already streamed into the Activity session's DAG rows (the same
    /// `cost_usd` trace steps that land in trace.jsonl), so credit that sum to
    /// the session cost meter — a `triage:run` that burns real dollars before
    /// a final provider error must not read as $0. Mirrors
    /// `record_tool_result_cost` (success path) and `record_agent_cost`
    /// (agent path).
    fn record_failed_tool_spent_cost(&mut self, state: &ToolEventState) {
        if let Some(cost_usd) = self.failed_tool_spent_cost_usd(state.run_id.as_deref()) {
            self.record_cost(cost_usd);
        }
    }

    /// Sum the trace-streamed spend for the failed run. Guarded on the run id
    /// so a stale Activity session from an earlier run is never billed to the
    /// wrong tool.
    fn failed_tool_spent_cost_usd(&self, run_id: Option<&str>) -> Option<f64> {
        let session = self.activity()?;
        if run_id != Some(session.run_id.as_str()) {
            return None;
        }
        let spent_usd: f64 = session.tasks.values().map(|row| row.cost_usd).sum();
        (spent_usd > 0.0).then_some(spent_usd)
    }

    /// Flip the failed tool's Activity DAG row to `Failing` so the progress
    /// pane stops spinning and reflects the error. The tool's producer bails on
    /// failure before emitting a terminal trace step, so we synthesize one here
    /// (mirrors `mark_scan_activity_failed` for the scan pipeline).
    fn mark_tool_activity_failed(&mut self, tool_name: &str, error: &str) {
        let Some(session) = self.activity_mut() else {
            return;
        };
        let (module_id, verb) = tool_name.split_once(':').unwrap_or((tool_name, "run"));
        session.apply_step(
            // 320 keeps the full remedy available to the Activity feed (which
            // wraps error rows); the on-disk trace artifact keeps its own cap.
            kuzushi_core::RunTraceStep::new(0, "refused", short_label(error, 320))
                .with_module_id(module_id)
                .with_verb(verb)
                .with_severity("danger"),
        );
        session.mark_incomplete_tasks_after_failure();
    }

    fn log_tool_failure(&mut self, tool_name: &str, message: String, abort_requested: bool) {
        if abort_requested {
            // The operator asked for the abort — record it, but don't pop an
            // error banner for an outcome they initiated.
            self.log(
                "error",
                format!("{tool_name} ended after abort request: {message}"),
            );
        } else {
            self.set_error_notice("tool", message);
        }
    }

    fn log_failure_context(&mut self, context: Option<FailureToLlmContext>) {
        if let Some(context) = context {
            self.log("failure-context", render_failure_context(&context));
            self.set_pending_failure_context(context);
        }
    }

    /// Capture the structured handoff context (for the failure-handoff view /
    /// failures.json) WITHOUT echoing it to the transcript. Used on the
    /// completed path, where a tool returned a usable result with a caveat
    /// (e.g. a scanner whose binary is missing) — the caveat is already shown
    /// in the tool's `result` line, so the verbose context would just be noise.
    fn capture_failure_context(&mut self, context: Option<FailureToLlmContext>) {
        if let Some(context) = context {
            self.set_pending_failure_context(context);
        }
    }

    pub(crate) fn apply_tool_result_state(
        &mut self,
        tool_name: &str,
        result: &serde_json::Value,
    ) -> Vec<ShellEffect> {
        let mut effects = self.tool_result_refresh_effects(tool_name);
        effects.extend(self.cache_tool_snapshot(tool_name, result));
        self.record_tool_result_cost(result);
        if tool_name == "module-recommender:recommend" {
            effects.extend(self.apply_model_recommendations(result));
        }
        effects
    }

    pub(crate) fn record_tool_run_effect(&mut self, record: ToolRunRecordEffect) {
        let target = record.target;
        let run_id = record.run_id;
        let tool_name = record.tool_name;
        match record.outcome {
            ToolRunRecordOutcome::Complete { result } => self.record_completed_tool_run(
                target.as_deref(),
                run_id.as_deref(),
                &tool_name,
                result,
            ),
            ToolRunRecordOutcome::Failed { error } => self.record_failed_tool_run(
                target.as_deref(),
                run_id.as_deref(),
                &tool_name,
                &error,
            ),
            ToolRunRecordOutcome::Canceled { reason } => {
                record_tool_run_canceled(target.as_deref(), run_id.as_deref(), &tool_name, &reason);
                self.log("result", format!("canceled · {tool_name} · {reason}"));
            }
            ToolRunRecordOutcome::Interrupted { reason } => {
                record_tool_run_interrupted(
                    target.as_deref(),
                    run_id.as_deref(),
                    &tool_name,
                    &reason,
                );
                self.log("result", format!("interrupted · {tool_name} · {reason}"));
            }
            ToolRunRecordOutcome::Refused { reason } => {
                record_tool_run_refused(target.as_deref(), run_id.as_deref(), &tool_name, &reason);
                self.log("result", format!("blocked · {tool_name} · {reason}"));
            }
        }
    }

    fn record_completed_tool_run(
        &mut self,
        target: Option<&Path>,
        run_id: Option<&str>,
        tool_name: &str,
        result: serde_json::Value,
    ) {
        let context = record_tool_run_complete(target, run_id, tool_name, &result);
        let result = result_with_fallback_context(target, run_id, result);
        self.log_tool_result(&result);
        self.capture_failure_context(context);
    }

    fn record_failed_tool_run(
        &mut self,
        target: Option<&Path>,
        run_id: Option<&str>,
        tool_name: &str,
        error: &str,
    ) {
        let context = record_tool_run_failed(target, run_id, tool_name, error);
        let result = failed_tool_result(target, run_id, tool_name, error);
        self.log_tool_result(&result);
        self.log_failure_context(context);
    }

    fn log_tool_result(&mut self, result: &serde_json::Value) {
        self.log("result", rendered_tool_result(result));
    }

    fn tool_result_refresh_effects(&self, tool_name: &str) -> Vec<ShellEffect> {
        let mut effects = Vec::new();
        if matches!(tool_name, "context:build" | "context-lite:index") {
            effects.push(ShellEffect::RefreshContextView);
        }
        if finding_state_tool(tool_name) {
            effects.push(ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None,
            }));
        }
        effects
    }

    fn record_tool_result_cost(&mut self, result: &serde_json::Value) {
        if let Some(cost_usd) = extract_cost_usd(result) {
            self.record_cost(cost_usd);
        }
    }
}

fn finding_state_tool(tool_name: &str) -> bool {
    matches!(tool_name, "triage:run" | "verify:finding" | "patch:finding")
}

/// Completion banner text. When the operator requested an abort but the tool
/// ignored the cancel token and returned a result anyway, the banner must not
/// claim a plain "✓ finished" — the Activity DAG row shows the run as
/// Canceled, and the two signifiers must not disagree about the same run.
fn tool_completion_notice(
    tool_name: &str,
    secs: u64,
    completed_after_cancel: bool,
    skipped: bool,
) -> String {
    let elapsed = crate::app::compact_secs(secs);
    if completed_after_cancel {
        format!("{tool_name} completed after cancel in {elapsed} — `/a` for the run feed")
    } else if skipped {
        format!("⊘ {tool_name} skipped in {elapsed} — `/a` for the run feed")
    } else {
        format!("✓ {tool_name} finished in {elapsed} — `/a` for the run feed")
    }
}

fn tool_result_is_skipped(result: &serde_json::Value) -> bool {
    result.get("status").and_then(serde_json::Value::as_str) == Some("skipped")
        || result
            .pointer("/data/status")
            .and_then(serde_json::Value::as_str)
            == Some("skipped")
}

fn tool_run_record_effect(
    state: &ToolEventState,
    tool_name: &str,
    outcome: ToolRunRecordOutcome,
) -> ShellEffect {
    ShellEffect::RecordToolRun(ToolRunRecordEffect {
        target: state.target.clone(),
        run_id: state.run_id.clone(),
        tool_name: tool_name.to_string(),
        outcome,
    })
}

fn rendered_tool_result(result: &serde_json::Value) -> String {
    result
        .get("output")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
        .or_else(|| generic_count_receipt(result))
        .unwrap_or_else(|| {
            serde_json::to_string_pretty(result).unwrap_or_else(|_| result.to_string())
        })
}

fn generic_count_receipt(result: &serde_json::Value) -> Option<String> {
    let count = result.pointer("/data/count")?.as_u64()?;
    Some(format!("completed · {count} records"))
}

fn result_with_fallback_context(
    target: Option<&Path>,
    run_id: Option<&str>,
    result: serde_json::Value,
) -> serde_json::Value {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return result;
    };
    output_with_run_fallback_context(target, run_id, result)
}

fn failed_tool_result(
    target: Option<&Path>,
    run_id: Option<&str>,
    tool_name: &str,
    error: &str,
) -> serde_json::Value {
    let result = failed_tool_output(tool_name, error, failed_tool_artifacts(target, run_id));
    result_with_fallback_context(target, run_id, result)
}

fn failed_tool_artifacts(target: Option<&Path>, run_id: Option<&str>) -> serde_json::Value {
    let (Some(target), Some(run_id)) = (target, run_id) else {
        return serde_json::json!([]);
    };
    load_run_summary(target, run_id)
        .ok()
        .and_then(|summary| serde_json::to_value(summary.artifacts).ok())
        .unwrap_or_else(|| serde_json::json!([]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::RunTraceStep;

    fn app_with_tool_session(tool_name: &str, run_id: &str) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_activity(Some(ActivitySession::new(run_id)));
        app.set_active_tool_run_id_for_test(run_id);
        app.set_running_tool_for_test(tool_name);
        app
    }

    fn stream_llm_cost_steps(app: &mut ShellApp, module_id: &str, verb: &str, costs: &[f64]) {
        let session = app.activity_mut().expect("activity session");
        session.apply_step(
            RunTraceStep::new(0, "tool", format!("{module_id}:{verb} start"))
                .with_module_id(module_id)
                .with_verb(verb),
        );
        for (n, cost) in costs.iter().enumerate() {
            session.apply_step(
                RunTraceStep::new(n + 1, "reasoning", "llm call")
                    .with_module_id(module_id)
                    .with_verb(verb)
                    .with_cost_usd(Some(*cost)),
            );
        }
    }

    #[test]
    fn failed_agentic_tool_credits_trace_streamed_cost_to_meter() {
        let mut app = app_with_tool_session("triage:run", "run-f4");
        stream_llm_cost_steps(&mut app, "triage", "run", &[0.03, 0.012]);

        app.apply_tool_event(ToolEvent::Failed {
            tool_name: "triage:run".to_string(),
            error: "Anthropic API 500 Internal Server Error".to_string(),
        });

        assert!(
            (app.session().session_cost_usd() - 0.042).abs() < 1e-9,
            "dollars spent before the provider error must reach the meter"
        );
        assert!(app
            .session()
            .last_tool_cost_usd()
            .is_some_and(|cost| (cost - 0.042).abs() < 1e-9));
    }

    #[test]
    fn failed_tool_does_not_bill_a_stale_session_from_another_run() {
        let mut app = app_with_tool_session("triage:run", "run-current");
        stream_llm_cost_steps(&mut app, "triage", "run", &[0.05]);
        // The session on screen belongs to an earlier run.
        app.activity_mut().expect("activity session").run_id = "run-older".to_string();

        app.apply_tool_event(ToolEvent::Failed {
            tool_name: "triage:run".to_string(),
            error: "provider error".to_string(),
        });

        assert_eq!(
            app.session().session_cost_usd(),
            0.0,
            "another run's spend must not be billed to this failure"
        );
    }

    #[test]
    fn tool_success_after_abort_banner_reads_completed_after_cancel() {
        let mut app = app_with_tool_session("triage:run", "run-f6");
        app.set_tool_abort_requested_for_test(true);

        app.apply_tool_event(ToolEvent::Finished {
            tool_name: "triage:run".to_string(),
            result: serde_json::json!({ "output": "done" }),
        });

        let notice = app.advisory().notice.as_ref().expect("completion banner");
        assert!(
            notice.message.contains("triage:run completed after cancel"),
            "banner must agree with the Canceled DAG row, got: {}",
            notice.message
        );
        assert!(
            !notice.message.contains("✓"),
            "no green check after a requested cancel, got: {}",
            notice.message
        );
    }

    #[test]
    fn tool_success_without_abort_keeps_plain_finished_banner() {
        let mut app = app_with_tool_session("triage:run", "run-ok");

        app.apply_tool_event(ToolEvent::Finished {
            tool_name: "triage:run".to_string(),
            result: serde_json::json!({ "output": "done" }),
        });

        let notice = app.advisory().notice.as_ref().expect("completion banner");
        assert!(
            notice.message.contains("✓ triage:run finished in"),
            "plain success keeps the existing wording, got: {}",
            notice.message
        );
    }
}
