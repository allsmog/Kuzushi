use super::*;
use kuzushi_core::run_artifacts::{
    load_run_summary, output_with_run_fallback_context, FailureToLlmContext,
};
use std::path::{Path, PathBuf};

struct ToolEventState {
    abort_reason: Option<AbortReason>,
    run_id: Option<String>,
    target: Option<PathBuf>,
    completion: Option<kuzushi_core::PendingToolCallCompletion>,
}

struct NamedToolTerminal {
    label: &'static str,
    reason: String,
    kind: ToolRunTerminalKind,
    completion: Option<kuzushi_core::PendingToolCallCompletion>,
}

fn tool_run_outcome_has_usable_result(outcome: &ToolRunRecordOutcome) -> bool {
    let result = match outcome {
        ToolRunRecordOutcome::Complete { result }
        | ToolRunRecordOutcome::ObservedComplete { result, .. } => result,
        _ => return false,
    };
    matches!(
        kuzushi_core::tool_result_status(result),
        kuzushi_core::ToolResultStatus::Completed | kuzushi_core::ToolResultStatus::Partial
    )
}

fn with_tool_completion(
    mut state: ToolEventState,
    completion: kuzushi_core::PendingToolCallCompletion,
) -> ToolEventState {
    state.completion = Some(completion);
    state
}

fn named_tool_terminal(outcome: ToolRunRecordOutcome) -> NamedToolTerminal {
    match outcome {
        ToolRunRecordOutcome::Canceled { reason } => canceled_terminal(reason, None),
        ToolRunRecordOutcome::Interrupted { reason } => interrupted_terminal(reason, None),
        ToolRunRecordOutcome::Refused { reason } => refused_terminal(reason, None),
        ToolRunRecordOutcome::ObservedCanceled { reason, completion } => {
            canceled_terminal(reason, Some(completion))
        }
        ToolRunRecordOutcome::ObservedInterrupted { reason, completion } => {
            interrupted_terminal(reason, Some(completion))
        }
        ToolRunRecordOutcome::ObservedRefused { reason, completion } => {
            refused_terminal(reason, Some(completion))
        }
        ToolRunRecordOutcome::Complete { .. }
        | ToolRunRecordOutcome::Failed { .. }
        | ToolRunRecordOutcome::ObservedComplete { .. }
        | ToolRunRecordOutcome::ObservedFailed { .. } => {
            unreachable!("result-bearing outcome handled before terminal persistence")
        }
    }
}

fn canceled_terminal(
    reason: String,
    completion: Option<kuzushi_core::PendingToolCallCompletion>,
) -> NamedToolTerminal {
    NamedToolTerminal {
        label: "canceled",
        reason,
        kind: ToolRunTerminalKind::Canceled,
        completion,
    }
}

fn interrupted_terminal(
    reason: String,
    completion: Option<kuzushi_core::PendingToolCallCompletion>,
) -> NamedToolTerminal {
    NamedToolTerminal {
        label: "interrupted",
        reason,
        kind: ToolRunTerminalKind::Interrupted,
        completion,
    }
}

fn refused_terminal(
    reason: String,
    completion: Option<kuzushi_core::PendingToolCallCompletion>,
) -> NamedToolTerminal {
    NamedToolTerminal {
        label: "blocked",
        reason,
        kind: ToolRunTerminalKind::Refused,
        completion,
    }
}

impl ShellApp {
    pub(crate) fn apply_tool_event(&mut self, event: ToolEvent) -> Vec<ShellEffect> {
        let state = self.take_tool_event_state();
        match event {
            ToolEvent::Finished { tool_name, result } => {
                self.apply_result_tool_event(state, tool_name, result)
            }
            ToolEvent::Failed { tool_name, error } => {
                self.apply_failed_tool_event(state, tool_name, error)
            }
            ToolEvent::Refused { tool_name, error } => {
                self.apply_refused_tool_event(state, tool_name, error)
            }
            ToolEvent::ObservedFinished {
                tool_name,
                result,
                completion,
            } => self.apply_result_tool_event(
                with_tool_completion(state, completion),
                tool_name,
                result,
            ),
            ToolEvent::ObservedFailed {
                tool_name,
                error,
                completion,
            } => self.apply_failed_tool_event(
                with_tool_completion(state, completion),
                tool_name,
                error,
            ),
        }
    }

    fn apply_result_tool_event(
        &mut self,
        state: ToolEventState,
        tool_name: String,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
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

    fn take_tool_event_state(&mut self) -> ToolEventState {
        let state = ToolEventState {
            abort_reason: self.tool_abort_reason(),
            run_id: self.take_active_tool_run_id(),
            target: self.take_active_tool_target(),
            completion: None,
        };
        self.finish_tool_run();
        state
    }

    fn apply_finished_tool_event(
        &mut self,
        mut state: ToolEventState,
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
            &mut state,
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
        mut state: ToolEventState,
        tool_name: String,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
        let message = failure_like_result_message(&result);
        if let Some(reason) = state.abort_reason {
            return self.apply_aborted_tool_event(state, tool_name, message, reason);
        }
        let mut effects = vec![tool_run_record_effect(
            &mut state,
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
        mut state: ToolEventState,
        tool_name: String,
        result: serde_json::Value,
    ) -> Vec<ShellEffect> {
        let message = failure_like_result_message(&result);
        if let Some(reason) = state.abort_reason {
            return self.apply_aborted_tool_event(state, tool_name, message, reason);
        }
        let mut effects = vec![tool_run_record_effect(
            &mut state,
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
        mut state: ToolEventState,
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
            &mut state,
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
            self.log(
                "scene",
                "threat model ready — open with `scene` and select DFD",
            );
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
        let planning_continues =
            self.engagement.running_tool_is(tool_name) && !self.engagement.planning_queues_empty();
        let same_task_continues = self.engagement.running_planning_task().map_or_else(
            || {
                self.engagement
                    .planning_tool_pending_after_current(tool_name)
            },
            |task| self.engagement.planning_task_pending_after_current(task),
        );
        if let Some(session) = self.activity_mut() {
            if !same_task_continues {
                session.mark_task_done(tool_name);
            }
            if !planning_continues {
                session.mark_incomplete_tasks_after_success(ActivityTerminalContext::Run);
            }
        }
    }

    fn mark_tool_activity_partial(&mut self, tool_name: &str, message: &str) {
        if let Some(session) = self.activity_mut() {
            session.mark_task_partial(tool_name, message);
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
        mut state: ToolEventState,
        tool_name: String,
        error: String,
    ) -> Vec<ShellEffect> {
        if let Some(reason) = state.abort_reason {
            return self.apply_aborted_tool_event(state, tool_name, error, reason);
        }
        let mut effects = vec![tool_run_record_effect(
            &mut state,
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
        mut state: ToolEventState,
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
                &mut state,
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
            &mut state,
            &tool_name,
            ToolRunRecordOutcome::Interrupted {
                reason: format!("{}: {error}", reason.label()),
            },
        )]
    }

    fn apply_refused_tool_event(
        &mut self,
        mut state: ToolEventState,
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
            &mut state,
            &tool_name,
            ToolRunRecordOutcome::Refused { reason: error },
        )]
    }

    /// A failed tool reports only an error string, so unlike the success path
    /// there is no result JSON carrying `costUsd`. The per-LLM-call spend has
    /// already streamed into the Activity session's DAG rows (the same
    /// terminal model-call items in `items.jsonl`), so credit that sum to
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
            Some(target) => kuzushi_core::run_artifacts::lifecycle_cost_report(target, run_id),
            None => self.activity().map_or(
                Ok(kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE),
                |session| session.runtime_cost_report(),
            ),
        }?;
        Ok(report)
    }

    /// Flip incomplete Activity tasks to failure. The producer's typed
    /// terminal item remains the authoritative failure detail.
    fn mark_tool_activity_failed(&mut self, tool_name: &str, error: &str) {
        let Some(session) = self.activity_mut() else {
            return;
        };
        session.mark_incomplete_tasks_after_failure();
        let _ = (tool_name, error);
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
        let run_id = record.run_id.clone();
        let persistence = self.persist_tool_run_outcome(
            record.target.as_deref(),
            record.run_id.as_deref(),
            &record.tool_name,
            record.outcome,
        );
        if let Err(error) = persistence {
            self.report_tool_terminal_persistence_failure(
                &record.tool_name,
                run_id.as_deref(),
                usable_result,
                error,
            );
        }
        self.invalidate_view_hydration();
        let mut cache = self.workbench_cache().borrow_mut();
        cache.invalidate_finding_patch_truth(None);
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
            ToolRunRecordOutcome::ObservedComplete { result, completion } => self
                .record_completed_tool_run_settled(target, run_id, tool_name, result, completion),
            ToolRunRecordOutcome::ObservedFailed { error, completion } => {
                self.record_failed_tool_run_settled(target, run_id, tool_name, &error, completion)
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
        let terminal = named_tool_terminal(outcome);
        let persistence = record_tool_run_terminal(
            target,
            run_id,
            tool_name,
            terminal.kind,
            &terminal.reason,
            terminal.completion,
        );
        self.log(
            "result",
            format!("{} · {tool_name} · {}", terminal.label, terminal.reason),
        );
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

    fn record_completed_tool_run_settled(
        &mut self,
        target: Option<&Path>,
        run_id: Option<&str>,
        tool_name: &str,
        result: serde_json::Value,
        completion: kuzushi_core::PendingToolCallCompletion,
    ) -> anyhow::Result<()> {
        match record_tool_run_complete_settled(target, run_id, tool_name, &result, completion) {
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

    fn record_failed_tool_run_settled(
        &mut self,
        target: Option<&Path>,
        run_id: Option<&str>,
        tool_name: &str,
        error: &str,
        completion: kuzushi_core::PendingToolCallCompletion,
    ) -> anyhow::Result<()> {
        let persistence =
            record_tool_run_failed_settled(target, run_id, tool_name, error, completion);
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
        run_id: Option<&str>,
        usable_result: bool,
        error: anyhow::Error,
    ) {
        self.record_tool_writer_fault(run_id, usable_result, &error);
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

    fn record_tool_writer_fault(
        &mut self,
        run_id: Option<&str>,
        execution_may_have_occurred: bool,
        error: &anyhow::Error,
    ) {
        let Some(fault) = error.downcast_ref::<kuzushi_core::run_lifecycle::RunItemWriterFault>()
        else {
            return;
        };
        let Some(activity) = self
            .activity_mut()
            .filter(|activity| Some(activity.run_id.as_str()) == run_id)
        else {
            return;
        };
        activity.record_run_item_writer_fault(
            fault
                .clone()
                .annotate_execution(execution_may_have_occurred),
        );
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
    state: &mut ToolEventState,
    tool_name: &str,
    mut outcome: ToolRunRecordOutcome,
) -> ShellEffect {
    if let Some(completion) = state.completion.take() {
        outcome = match outcome {
            ToolRunRecordOutcome::Complete { result } => {
                ToolRunRecordOutcome::ObservedComplete { result, completion }
            }
            ToolRunRecordOutcome::Failed { error } => {
                ToolRunRecordOutcome::ObservedFailed { error, completion }
            }
            ToolRunRecordOutcome::Canceled { reason } => {
                ToolRunRecordOutcome::ObservedCanceled { reason, completion }
            }
            ToolRunRecordOutcome::Interrupted { reason } => {
                ToolRunRecordOutcome::ObservedInterrupted { reason, completion }
            }
            ToolRunRecordOutcome::Refused { reason } => {
                ToolRunRecordOutcome::ObservedRefused { reason, completion }
            }
            observed => observed,
        };
    }
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

    fn app_with_tool_session(tool_name: &str, run_id: &str) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_activity(Some(ActivitySession::new(run_id)));
        app.set_active_tool_run_id_for_test(run_id);
        app.set_running_tool_for_test(tool_name);
        app
    }

    fn stream_llm_cost_steps(app: &mut ShellApp, _module_id: &str, _verb: &str, costs: &[f64]) {
        let session = app.activity_mut().expect("activity session");
        for cost in costs {
            apply_model_cost(session, *cost);
        }
    }

    fn apply_model_cost(session: &mut ActivitySession, cost_usd: f64) {
        use kuzushi_core::run_lifecycle::{RunCallId, RunItemId};
        let seq = session.run_projection.last_committed_seq + 1;
        let cost = kuzushi_core::runtime::RuntimeCost::from_usd(cost_usd, "test").unwrap();
        let item_id = RunItemId::new();
        let call_id = RunCallId::new();
        let started = test_model_started(session, seq, item_id, call_id);
        session.apply_run_item(started).unwrap();
        let finished = test_model_finished(session, seq + 1, item_id, call_id, cost);
        session.apply_run_item(finished).unwrap();
    }

    fn test_model_started(
        session: &ActivitySession,
        seq: u64,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
    ) -> kuzushi_core::run_lifecycle::RunItemEnvelopeV1 {
        use kuzushi_core::run_lifecycle::*;
        RunItemEnvelopeV1::new(
            seq,
            RunId::parse(&session.run_id).unwrap(),
            item_id,
            RunItemSource::Runtime,
            RunItemV1::ModelCallStarted {
                provider: SafeText::operator_visible("test"),
                model: SafeText::operator_visible("test:model"),
                operation_fingerprint: OperationFingerprint::from_bytes(b"test model call"),
            },
            session.run_projection.last_event_hash.clone(),
        )
        .unwrap()
        .with_call(call_id)
        .unwrap()
    }

    fn test_model_finished(
        session: &ActivitySession,
        seq: u64,
        item_id: kuzushi_core::run_lifecycle::RunItemId,
        call_id: kuzushi_core::run_lifecycle::RunCallId,
        cost: kuzushi_core::runtime::RuntimeCost,
    ) -> kuzushi_core::run_lifecycle::RunItemEnvelopeV1 {
        use kuzushi_core::run_lifecycle::*;
        RunItemEnvelopeV1::new(
            seq,
            RunId::parse(&session.run_id).unwrap(),
            item_id,
            RunItemSource::Runtime,
            RunItemV1::ModelCallFinished {
                provider: SafeText::operator_visible("test"),
                model: SafeText::operator_visible("test:model"),
                status: RunItemStatus::Completed,
                latency_ms: 10,
                usage: ModelUsage {
                    input_tokens: Some(1),
                    output_tokens: Some(1),
                },
                cost: kuzushi_core::runtime::RuntimeCostReport::known(cost),
                error_class: None,
                failure: None,
            },
            session.run_projection.last_event_hash.clone(),
        )
        .unwrap()
        .with_call(call_id)
        .unwrap()
    }

    #[test]
    fn tool_writer_fault_annotation_tracks_usable_execution() {
        use kuzushi_core::run_lifecycle::{
            PersistenceFailureStage, RunDurabilityHealth, RunItemWriterFault, SafeText,
        };
        let fault = RunItemWriterFault {
            stage: PersistenceFailureStage::Sync,
            last_durable_seq: 4,
            detail: SafeText::operator_visible("terminal sync failed"),
            execution_may_have_occurred: false,
        };
        let mut app = app_with_tool_session("triage:run", "run-post-exec");

        app.report_tool_terminal_persistence_failure(
            "triage:run",
            Some("run-post-exec"),
            true,
            anyhow::Error::new(fault),
        );

        assert!(matches!(
            app.activity().unwrap().effective_run_lifecycle_health().durability,
            RunDurabilityHealth::Failed {
                execution_may_have_occurred: true,
                ref detail,
                ..
            } if detail.as_str().contains("do not retry automatically")
        ));
    }

    #[test]
    fn completed_plan_step_keeps_remaining_checklist_rows_queued() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.engagement
            .queue_plan(vec![crate::app::PlanningTaskId::MapEntryPoints]);
        app.engagement.set_running_tool("context:build".to_string());
        let mut session = ActivitySession::new("run-context");
        session.seed_task_sequence(app.engagement.planning_tool_sequence());
        app.set_activity(Some(session));

        app.mark_tool_activity_complete("context:build");

        let session = app.activity().expect("plan activity");
        assert_eq!(session.tasks["context:build"].state, DagTaskState::Done);
        assert_eq!(
            session.tasks["entry-points:extract"].state,
            DagTaskState::Queued
        );
    }

    #[test]
    fn batched_plan_row_stays_active_until_its_final_invocation() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let repeated = crate::app::PlanningTaskId::VerifyFindings;
        app.engagement.replace_expanded_steps(vec![PlanningRunStep {
            task: repeated,
            tool_name: "verify:finding".to_string(),
            input: serde_json::json!({"fingerprint": "second"}),
        }]);
        app.engagement
            .set_running_tool("verify:finding".to_string());
        let mut session = ActivitySession::new("verify-first");
        session.seed_task_sequence(app.engagement.planning_tool_sequence());
        session.tasks.get_mut("verify:finding").unwrap().state = DagTaskState::Active;
        app.set_activity(Some(session));

        app.mark_tool_activity_complete("verify:finding");

        assert_eq!(
            app.activity().unwrap().tasks["verify:finding"].state,
            DagTaskState::Active
        );
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
    fn refused_tool_is_blocked_live_in_replay_and_in_the_run_summary() {
        use kuzushi_core::run_lifecycle::{present_run, RunItemStatus};

        let target = tempfile::tempdir().unwrap();
        let run_id = "tool-refused-blocked";
        let record = ToolRunRecord::new(target.path(), run_id, "tool", "sast:scan");
        try_record_tool_run_started_with_reproducibility(
            record,
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();

        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target.path().to_path_buf()));
        app.set_activity(Some(ActivitySession::new(run_id)));
        app.set_active_tool_run_id_for_test(run_id);
        app.set_running_tool_for_test("sast:scan");
        let effects = app.apply_tool_event(ToolEvent::Refused {
            tool_name: "sast:scan".to_string(),
            error: "autonomy posture allows work through Review".to_string(),
        });

        assert_eq!(
            app.activity().unwrap().tasks["sast:scan"].state,
            DagTaskState::Blocked
        );

        crate::app::EffectRuntime::execute(&mut app, effects);

        let summary = load_run_summary(target.path(), run_id).unwrap();
        assert_eq!(summary.status, "blocked");
        let read = kuzushi_core::run_lifecycle::load_run_projection(target.path(), run_id).unwrap();
        assert_eq!(
            read.projection.terminal.as_ref().map(|item| item.status),
            Some(RunItemStatus::Blocked)
        );
        assert_eq!(
            present_run(&read).terminal_status,
            Some(RunItemStatus::Blocked)
        );
    }
}
