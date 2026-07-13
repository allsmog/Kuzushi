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

fn tool_run_outcome_has_usable_result(outcome: &ToolRunRecordOutcome) -> bool {
    let ToolRunRecordOutcome::Complete { result } = outcome else {
        return false;
    };
    matches!(
        kuzushi_core::tool_result_status(result),
        kuzushi_core::ToolResultStatus::Completed | kuzushi_core::ToolResultStatus::Partial
    )
}

impl ShellApp {
    pub(crate) fn apply_tool_event(&mut self, event: ToolEvent) -> Vec<ShellEffect> {
        let state = self.take_tool_event_state();
        match event {
            ToolEvent::Finished { tool_name, result } => {
                match kuzushi_core::tool_result_status(&result) {
                    kuzushi_core::ToolResultStatus::Completed => {
                        self.apply_finished_tool_event(state, tool_name, result)
                    }
                    kuzushi_core::ToolResultStatus::Partial => {
                        self.apply_partial_tool_result(state, tool_name, result)
                    }
                    kuzushi_core::ToolResultStatus::Skipped => {
                        self.apply_skipped_tool_result(state, tool_name, result)
                    }
                    kuzushi_core::ToolResultStatus::Failed => {
                        self.apply_failed_result_envelope(state, tool_name, result)
                    }
                }
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
            target: self.take_active_tool_target(),
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
        effects.extend(self.apply_tool_result_state(&tool_name, state.run_id.as_deref(), &result));
        self.finish_completed_tool_ui(&tool_name, state.abort_reason.is_some());
        effects.extend(self.finished_tool_continuation(&tool_name, state.abort_reason.is_none()));
        effects
    }

    fn apply_partial_tool_result(
        &mut self,
        state: ToolEventState,
        tool_name: String,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
        let message = failure_like_result_message(&result);
        if let Some(reason) = state.abort_reason {
            return self.apply_aborted_tool_event(state, tool_name, message, reason);
        }
        let mut effects = vec![tool_run_record_effect(
            &state,
            &tool_name,
            ToolRunRecordOutcome::Complete {
                result: result.clone(),
            },
        )];
        effects.extend(self.apply_tool_result_state(&tool_name, state.run_id.as_deref(), &result));
        self.mark_tool_activity_partial(&tool_name, &message);
        self.set_partial_activity(tool_name.clone(), "usable partial result retained");
        self.set_warn_notice("tool", format!("{tool_name} partial: {message}"));
        self.abort_pending_chain(&tool_name);
        if self.engagement.running_tool_is(&tool_name) {
            self.pause_planning_task_after_failure(&tool_name, &message);
        }
        effects
    }

    fn apply_failed_result_envelope(
        &mut self,
        state: ToolEventState,
        tool_name: String,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
        let message = failure_like_result_message(&result);
        if let Some(reason) = state.abort_reason {
            return self.apply_aborted_tool_event(state, tool_name, message, reason);
        }
        let mut effects = vec![tool_run_record_effect(
            &state,
            &tool_name,
            ToolRunRecordOutcome::Complete {
                result: result.clone(),
            },
        )];
        effects.extend(self.tool_result_refresh_effects(&tool_name));
        self.record_tool_result_cost(&tool_name, state.run_id.as_deref(), &result);
        self.mark_tool_activity_failed(&tool_name, &message);
        self.log_tool_failure(
            &tool_name,
            with_next_step(message.clone(), "tools, options <tool>, or model <n>"),
            false,
        );
        self.set_failed_activity(tool_name.clone(), "tool returned a failed result");
        self.abort_pending_chain(&tool_name);
        if self.engagement.running_tool_is(&tool_name) {
            self.pause_planning_task_after_failure(&tool_name, &message);
        }
        effects
    }

    fn apply_skipped_tool_result(
        &mut self,
        state: ToolEventState,
        tool_name: String,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
        if let Some(reason) = state.abort_reason {
            return self.apply_aborted_tool_event(
                state,
                tool_name,
                "tool returned skipped after abort request".to_string(),
                reason,
            );
        }
        let mut effects = vec![tool_run_record_effect(
            &state,
            &tool_name,
            ToolRunRecordOutcome::Complete {
                result: result.clone(),
            },
        )];
        effects.extend(self.tool_result_refresh_effects(&tool_name));
        self.record_tool_result_cost(&tool_name, state.run_id.as_deref(), &result);
        self.mark_tool_activity_skipped(&tool_name);
        self.set_skipped_activity(tool_name.clone(), "tool reported skipped");
        self.set_info_notice(
            "tool",
            format!("⊘ {tool_name} skipped — no continuation started"),
        );
        self.abort_pending_chain(&tool_name);
        if self.engagement.running_tool_is(&tool_name) {
            self.engagement.pause_planning_queue();
            self.log(
                "planning",
                format!("plan paused after {tool_name} was skipped"),
            );
        }
        effects
    }

    fn finish_completed_tool_ui(&mut self, tool_name: &str, abort_requested: bool) {
        self.set_completed_activity(tool_name.to_string(), "tool result applied");
        self.mark_tool_activity_complete(tool_name);
        self.record_tool_duration_and_notify(tool_name, abort_requested);
        self.auto_open_viz_for_tool(tool_name);
        self.auto_open_recon_output(tool_name);
    }

    fn auto_open_recon_output(&mut self, tool_name: &str) {
        if !tool_name.starts_with("recon:") || self.recon_continuation_pending(tool_name) {
            return;
        }
        let has_evidence = self
            .domain()
            .recon_snapshot()
            .is_some_and(ReconSnapshot::has_evidence);
        if !has_evidence || self.activity().is_none() || !self.ui().auto_open_activity() {
            return;
        }
        if !self.router.activity().can_auto_switch_deck() {
            self.log(
                "recon",
                "recon evidence ready — output page unchanged; cycle to the recon view",
            );
            return;
        }
        self.router
            .activity_mut()
            .set_deck_page(ActivityDeckPage::Recon);
        self.log("recon", "recon evidence ready — showing in Activity output");
    }

    fn recon_continuation_pending(&self, tool_name: &str) -> bool {
        self.engagement.has_pending_chain()
            || self.engagement.running_tool_is(tool_name)
            || !self.engagement.planning_queues_empty()
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
    fn mark_tool_activity_complete(&mut self, tool_name: &str) {
        if let Some(session) = self.activity_mut() {
            session.mark_task_done(tool_name);
            session.mark_incomplete_tasks_after_success(ActivityTerminalContext::Run);
        }
    }

    fn mark_tool_activity_partial(&mut self, tool_name: &str, message: &str) {
        if let Some(session) = self.activity_mut() {
            session.mark_task_partial(tool_name, message);
            session.mark_incomplete_tasks_after_failure();
        }
    }

    fn mark_tool_activity_skipped(&mut self, tool_name: &str) {
        if let Some(session) = self.activity_mut() {
            session.mark_task_skipped(tool_name);
            session.mark_incomplete_tasks_after_skipped();
        }
    }

    /// Feed the ETA history and — when the operator is on another view —
    /// raise the completion banner so background work announces itself
    /// instead of finishing silently (ambient-progress story).
    fn record_tool_duration_and_notify(&mut self, tool_name: &str, completed_after_cancel: bool) {
        let Some(secs) = self.completed_tool_secs(tool_name) else {
            return;
        };
        self.record_task_duration_secs(tool_name, secs);
        if matches!(self.shell_view(), ShellView::Activity) {
            return;
        }
        self.set_success_notice(
            "run",
            tool_completion_notice(tool_name, secs, completed_after_cancel),
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
        Some(row_secs.unwrap_or_else(|| session.elapsed_secs()))
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
        self.set_failed_activity(
            tool_name.clone(),
            "tool failed before producing a usable result",
        );
        self.abort_pending_chain(&tool_name);
        if self.engagement.running_tool_is(&tool_name) {
            self.pause_planning_task_after_failure(&tool_name, &error);
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
        let no_call = kuzushi_core::runtime::RuntimeCostReport::known(
            kuzushi_core::runtime::RuntimeCost::ZERO,
        );
        match state.run_id.as_deref() {
            Some(run_id) => self.settle_run_cost_report(run_id, no_call),
            None => self.record_cost_report(no_call),
        }
        if let Some(session) = self.activity_mut() {
            session.mark_task_blocked(&tool_name, &error);
            session.mark_terminal();
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
        match self.failed_tool_spent_cost_report(state) {
            Ok(cost) => match state.run_id.as_deref() {
                Some(run_id) => self.settle_run_cost_report(run_id, cost),
                None => self.record_cost_report(cost),
            },
            Err(error) => self.report_cost_accounting_error(error),
        }
    }

    /// Read checked, run-bound model-call spend. A stale Activity session is
    /// never billed to the current tool, and a workspace-free run falls back
    /// to the same checked in-memory terminal-call projection.
    fn failed_tool_spent_cost_report(
        &self,
        state: &ToolEventState,
    ) -> anyhow::Result<kuzushi_core::runtime::RuntimeCostReport> {
        let Some(run_id) = state.run_id.as_deref() else {
            return Ok(kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE);
        };
        if self
            .activity()
            .is_some_and(|session| session.run_id != run_id)
        {
            return Ok(kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE);
        }
        let report = match state.target.as_deref() {
            Some(target) => kuzushi_core::run_artifacts::trace_cost_report(target, run_id),
            None => self.activity().map_or(
                Ok(kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE),
                |session| session.runtime_cost_report(),
            ),
        }?;
        Ok(report)
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
        run_id: Option<&str>,
        result: &serde_json::Value,
    ) -> Vec<ShellEffect> {
        let mut effects = self.tool_result_refresh_effects(tool_name);
        effects.extend(self.cache_tool_snapshot(tool_name, result));
        self.record_tool_result_cost(tool_name, run_id, result);
        if tool_name == "module-recommender:recommend" {
            effects.extend(self.apply_model_recommendations(result));
        }
        effects
    }

    pub(crate) fn record_tool_run_effect(&mut self, record: ToolRunRecordEffect) {
        let usable_result = tool_run_outcome_has_usable_result(&record.outcome);
        let persistence = self.persist_tool_run_outcome(
            record.target.as_deref(),
            record.run_id.as_deref(),
            &record.tool_name,
            record.outcome,
        );
        if let Err(error) = persistence {
            self.report_tool_terminal_persistence_failure(&record.tool_name, usable_result, error);
        }
        self.invalidate_view_hydration();
        let mut cache = self.workbench_cache().borrow_mut();
        cache.invalidate_run_summaries();
        cache.invalidate_workspace_files();
    }

    fn persist_tool_run_outcome(
        &mut self,
        target: Option<&Path>,
        run_id: Option<&str>,
        tool_name: &str,
        outcome: ToolRunRecordOutcome,
    ) -> anyhow::Result<()> {
        match outcome {
            ToolRunRecordOutcome::Complete { result } => {
                self.record_completed_tool_run(target, run_id, tool_name, result)
            }
            ToolRunRecordOutcome::Failed { error } => {
                self.record_failed_tool_run(target, run_id, tool_name, &error)
            }
            terminal => self.persist_terminal_tool_run(target, run_id, tool_name, terminal),
        }
    }

    fn persist_terminal_tool_run(
        &mut self,
        target: Option<&Path>,
        run_id: Option<&str>,
        tool_name: &str,
        outcome: ToolRunRecordOutcome,
    ) -> anyhow::Result<()> {
        match outcome {
            ToolRunRecordOutcome::Canceled { reason } => self.persist_named_tool_terminal(
                target,
                run_id,
                tool_name,
                "canceled",
                reason,
                record_tool_run_canceled,
            ),
            ToolRunRecordOutcome::Interrupted { reason } => self.persist_named_tool_terminal(
                target,
                run_id,
                tool_name,
                "interrupted",
                reason,
                record_tool_run_interrupted,
            ),
            ToolRunRecordOutcome::Refused { reason } => self.persist_named_tool_terminal(
                target,
                run_id,
                tool_name,
                "blocked",
                reason,
                record_tool_run_refused,
            ),
            ToolRunRecordOutcome::Complete { .. } | ToolRunRecordOutcome::Failed { .. } => {
                unreachable!("result-bearing outcome handled before terminal persistence")
            }
        }
    }

    fn persist_named_tool_terminal(
        &mut self,
        target: Option<&Path>,
        run_id: Option<&str>,
        tool_name: &str,
        label: &str,
        reason: String,
        persist: fn(Option<&Path>, Option<&str>, &str, &str) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let persistence = persist(target, run_id, tool_name, &reason);
        self.log("result", format!("{label} · {tool_name} · {reason}"));
        persistence
    }

    fn record_completed_tool_run(
        &mut self,
        target: Option<&Path>,
        run_id: Option<&str>,
        tool_name: &str,
        result: serde_json::Value,
    ) -> anyhow::Result<()> {
        match record_tool_run_complete(target, run_id, tool_name, &result) {
            Ok(context) => {
                let result = result_with_fallback_context(target, run_id, result);
                self.log_tool_result(&result);
                self.capture_failure_context(context);
                Ok(())
            }
            Err(error) => {
                self.log_tool_result(&result);
                Err(error)
            }
        }
    }

    fn record_failed_tool_run(
        &mut self,
        target: Option<&Path>,
        run_id: Option<&str>,
        tool_name: &str,
        error: &str,
    ) -> anyhow::Result<()> {
        let persistence = record_tool_run_failed(target, run_id, tool_name, error);
        let result = failed_tool_result(target, run_id, tool_name, error);
        self.log_tool_result(&result);
        match persistence {
            Ok(context) => {
                self.log_failure_context(context);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn report_tool_terminal_persistence_failure(
        &mut self,
        tool_name: &str,
        usable_result: bool,
        error: anyhow::Error,
    ) {
        let message = format!(
            "{tool_name} result retained, but run artifacts could not be finalized: {error}"
        );
        self.log("error", message.clone());
        self.set_error_notice("artifacts", message);
        if usable_result {
            self.mark_tool_activity_partial(tool_name, "run artifact finalization failed");
            self.set_partial_activity(
                tool_name.to_string(),
                "result retained; replay artifacts are incomplete",
            );
        } else {
            self.mark_tool_activity_failed(tool_name, "run artifact finalization failed");
            self.set_failed_activity(
                tool_name.to_string(),
                "tool did not produce a usable result and terminal artifacts are incomplete",
            );
        }
    }

    fn log_tool_result(&mut self, result: &serde_json::Value) {
        self.log("result", rendered_tool_result(result));
    }

    fn tool_result_refresh_effects(&self, tool_name: &str) -> Vec<ShellEffect> {
        let mut effects = Vec::new();
        if matches!(tool_name, "context:build" | "context-lite:index") {
            effects.push(ShellEffect::RefreshContextView);
        }
        if self.registry().tool_requires_finding_store(tool_name) {
            effects.push(ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None,
            }));
        }
        effects
    }

    fn record_tool_result_cost(
        &mut self,
        tool_name: &str,
        run_id: Option<&str>,
        result: &serde_json::Value,
    ) {
        match extract_cost_report(result) {
            Ok(cost) => self.settle_tool_result_cost(tool_name, run_id, cost),
            Err(error) => self.report_cost_accounting_error(error),
        }
    }

    fn settle_tool_result_cost(
        &mut self,
        tool_name: &str,
        run_id: Option<&str>,
        cost: kuzushi_core::runtime::RuntimeCostReport,
    ) {
        if let Some(run_id) = run_id {
            self.settle_run_cost_report(run_id, cost);
            return;
        }
        let runtime_possible = self.registry().resolve_tool(tool_name).is_some_and(|tool| {
            tool.runtime_requirement != kuzushi_core::modules::RuntimeRequirement::Never
        });
        let cost = if cost.is_unavailable() && !runtime_possible {
            kuzushi_core::runtime::RuntimeCostReport::known(
                kuzushi_core::runtime::RuntimeCost::ZERO,
            )
        } else {
            cost
        };
        self.record_cost_report(cost);
    }
}

/// Completion banner text. When the operator requested an abort but the tool
/// ignored the cancel token and returned a result anyway, the banner must not
/// claim a plain "✓ finished" — the Activity DAG row shows the run as
/// Canceled, and the two signifiers must not disagree about the same run.
fn tool_completion_notice(tool_name: &str, secs: u64, completed_after_cancel: bool) -> String {
    let elapsed = crate::app::compact_secs(secs);
    if completed_after_cancel {
        format!("{tool_name} completed after cancel in {elapsed} — `/a` for the run feed")
    } else {
        format!("✓ {tool_name} finished in {elapsed} — `/a` for the run feed")
    }
}

fn failure_like_result_message(result: &serde_json::Value) -> String {
    result
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            result
                .get("errors")
                .and_then(serde_json::Value::as_array)
                .and_then(|errors| errors.first())
                .and_then(serde_json::Value::as_str)
        })
        .or_else(|| result.get("output").and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|message| !message.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| "tool returned a failed or partial result".to_string())
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
    use crate::ui_view_models::{jobs_registry_model, JobRunStatus};
    use kuzushi_core::run_artifacts::{
        load_run_summary, try_record_tool_run_canceled,
        try_record_tool_run_started_with_reproducibility, ToolRunRecord,
    };
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
                    .with_latency_ms(Some(10))
                    .with_cost_usd(Some(*cost))
                    .with_model_metadata("test:model", "test", format!("prompt-{n}")),
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
    fn failed_agentic_tool_preserves_explicit_zero_receipt() {
        let mut app = app_with_tool_session("triage:run", "run-zero");
        stream_llm_cost_steps(&mut app, "triage", "run", &[0.0]);

        app.apply_tool_event(ToolEvent::Failed {
            tool_name: "triage:run".to_string(),
            error: "provider returned a zero-cost receipt before failure".to_string(),
        });

        assert!(app.session().cost_accounting_is_complete());
        assert_eq!(app.session().last_tool_cost_usd(), Some(0.0));
    }

    #[test]
    fn failed_tool_does_not_bill_a_stale_session_from_another_run() {
        let mut app = app_with_tool_session("triage:run", "run-current");
        stream_llm_cost_steps(&mut app, "triage", "run", &[0.05]);
        // The session on screen belongs to an earlier run.
        app.set_activity_run_id("run-older".to_string());

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
    fn invalid_tool_result_cost_fails_session_accounting_closed() {
        let mut app = app_with_tool_session("triage:run", "run-invalid-cost");
        app.session_mut().set_session_budget_usd(Some(1.0));

        app.apply_tool_event(ToolEvent::Finished {
            tool_name: "triage:run".to_string(),
            result: serde_json::json!({"ok": true, "costUsd": -0.01}),
        });

        assert!(app.session().cost_accounting_error().is_some());
        assert!(app.is_budget_halted());
    }

    #[test]
    fn unresolved_tool_result_cost_is_not_presented_as_exact() {
        let mut app = app_with_tool_session("triage:run", "run-unresolved-cost");
        app.session_mut().set_session_budget_usd(Some(1.0));

        app.apply_tool_event(ToolEvent::Finished {
            tool_name: "triage:run".to_string(),
            result: serde_json::json!({
                "ok": true,
                "observedCostUsd": 0.01,
                "providerSpendUnresolved": true
            }),
        });

        assert_eq!(app.session().session_cost_usd(), 0.01);
        assert!(!app.session().cost_accounting_is_complete());
        assert!(app.is_budget_halted());
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

    #[test]
    fn canceled_sast_tool_remains_canceled_in_run_summary_and_jobs() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "tool-canceled-sast";
        let record = ToolRunRecord::new(target.path(), run_id, "tool", "sast:scan");
        try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        try_record_tool_run_canceled(record, "operator cancel: scan cancelled").unwrap();

        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target.path().to_path_buf()));
        app.set_activity(Some(ActivitySession::new(run_id)));
        app.set_active_tool_run_id_for_test(run_id);
        app.set_running_tool_for_test("sast:scan");
        app.set_tool_abort_requested_for_test(true);
        let effects = app.apply_tool_event(ToolEvent::Failed {
            tool_name: "sast:scan".to_string(),
            error: "scan cancelled".to_string(),
        });
        crate::app::EffectRuntime::execute(&mut app, effects);

        let summary = load_run_summary(target.path(), run_id).unwrap();
        assert_eq!(summary.status, "canceled");
        assert!(!app.advisory().notice.as_ref().is_some_and(|notice| {
            notice
                .message
                .contains("run artifacts could not be finalized")
        }));
        app.hydrate_active_view_blocking();
        let jobs = jobs_registry_model(&app, 5);
        let row = jobs
            .rows
            .iter()
            .find(|row| row.run_id == run_id)
            .expect("canceled run remains visible in Jobs");
        assert_eq!(row.status, JobRunStatus::Canceled);
    }

    #[test]
    fn standalone_recon_completion_selects_structured_activity_output() {
        let mut app = app_with_tool_session("recon:import", "run-recon");
        app.set_shell_view(ShellView::Activity);

        app.apply_tool_event(ToolEvent::Finished {
            tool_name: "recon:import".to_string(),
            result: recon_result(true),
        });

        assert_eq!(app.router.activity().deck_page, ActivityDeckPage::Recon);
        assert!(!app.router.activity().deck_page_pinned_by_user);
        assert!(app.log_lines().iter().any(|line| {
            line.prefix == "recon" && line.body.contains("showing in Activity output")
        }));
    }

    #[test]
    fn empty_recon_result_does_not_replace_the_output_page() {
        let mut app = app_with_tool_session("recon:import", "run-recon-empty");
        app.set_shell_view(ShellView::Activity);

        app.apply_tool_event(ToolEvent::Finished {
            tool_name: "recon:import".to_string(),
            result: recon_result(false),
        });

        assert_eq!(app.router.activity().deck_page, ActivityDeckPage::Findings);
    }

    #[test]
    fn recon_completion_respects_pinned_output_and_planning_continuations() {
        let mut pinned = app_with_tool_session("recon:import", "run-recon-pinned");
        pinned
            .router
            .activity_mut()
            .set_deck_page_by_user(ActivityDeckPage::Dfd);
        pinned.apply_tool_event(ToolEvent::Finished {
            tool_name: "recon:import".to_string(),
            result: recon_result(true),
        });
        assert_eq!(pinned.router.activity().deck_page, ActivityDeckPage::Dfd);

        let mut planned = app_with_tool_session("recon:import", "run-recon-planned");
        planned
            .engagement
            .queue_plan(vec![crate::app::PlanningTaskId::GatherRepoContext]);
        planned.apply_tool_event(ToolEvent::Finished {
            tool_name: "recon:import".to_string(),
            result: recon_result(true),
        });
        assert_eq!(
            planned.router.activity().deck_page,
            ActivityDeckPage::Findings
        );
    }

    fn recon_result(with_evidence: bool) -> serde_json::Value {
        let (hosts, services, notes) = if with_evidence {
            (
                serde_json::json!([{
                    "id": "h1", "workspaceId": "ws", "address": "192.0.2.10",
                    "hostname": "acme.example", "state": "alive"
                }]),
                serde_json::json!([{
                    "id": "s1", "hostId": "h1", "port": 443, "proto": "tcp",
                    "name": "https", "state": "open"
                }]),
                serde_json::json!([{
                    "id": "n1", "workspaceId": "ws", "hostId": "h1",
                    "serviceId": "s1", "ntype": "httpx", "data": { "status-code": 200 }
                }]),
            )
        } else {
            (
                serde_json::json!([]),
                serde_json::json!([]),
                serde_json::json!([]),
            )
        };
        serde_json::json!({
            "ok": true,
            "data": {
                "tool": "recon:import", "target": "httpx.json",
                "hosts": hosts, "services": services, "notes": notes
            }
        })
    }
}
