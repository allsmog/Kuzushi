use super::*;
use kuzushi_core::run_artifacts::{
    load_run_summary, output_with_run_fallback_context, FailureToLlmContext,
};
use std::path::{Path, PathBuf};

struct ToolEventState {
    abort_requested: bool,
    run_id: Option<String>,
    target: Option<PathBuf>,
}

impl ShellApp {
    pub(crate) fn apply_tool_event(&mut self, event: ToolEvent) {
        let state = self.take_tool_event_state();
        match event {
            ToolEvent::Finished { tool_name, result } => {
                self.apply_finished_tool_event(state, tool_name, result);
            }
            ToolEvent::Failed { tool_name, error } => {
                self.apply_failed_tool_event(state, tool_name, error);
            }
        }
    }

    fn take_tool_event_state(&mut self) -> ToolEventState {
        let state = ToolEventState {
            abort_requested: self.tool_abort_requested,
            run_id: self.tool_run_id.take(),
            target: self.target.clone(),
        };
        self.tool_running = None;
        self.tool_cancel = None;
        self.ambient_tool = None;
        self.active_model_override = None;
        self.tool_abort_requested = false;
        state
    }

    fn apply_finished_tool_event(
        &mut self,
        state: ToolEventState,
        tool_name: String,
        result: serde_json::Value,
    ) {
        let failure_context = record_tool_run_complete(
            state.target.as_deref(),
            state.run_id.as_deref(),
            &tool_name,
            &result,
        );
        let result =
            result_with_fallback_context(state.target.as_deref(), state.run_id.as_deref(), result);
        if state.abort_requested {
            self.log(
                "tool",
                format!("{tool_name} completed after abort request; applying completed result"),
            );
        }
        self.apply_tool_result(&tool_name, result);
        self.capture_failure_context(failure_context);
        self.set_completed_activity(tool_name.clone(), "tool result applied");
        self.mark_tool_activity_complete(&tool_name);
        self.record_tool_duration_and_notify(&tool_name);
        self.auto_open_viz_for_tool(&tool_name);
        self.advance_chain_after_tool(&tool_name);
        self.advance_planning_queue_after_tool(&tool_name);
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
        if let Some(session) = self.activity.as_mut() {
            session.mark_task_done(tool_name);
        }
    }

    /// Feed the ETA history and — when the operator is on another view —
    /// raise the green completion banner so background work announces
    /// itself instead of finishing silently (ambient-progress story).
    fn record_tool_duration_and_notify(&mut self, tool_name: &str) {
        let Some(secs) = self.completed_tool_secs(tool_name) else {
            return;
        };
        self.task_durations.record_secs(tool_name, secs);
        if matches!(self.shell_view, ShellView::Activity) {
            return;
        }
        self.set_success_notice(
            "run",
            format!(
                "✓ {tool_name} finished in {} — `/a` for the run feed",
                crate::app::compact_secs(secs)
            ),
        );
    }

    /// Wall-clock for the finished tool: its DAG row when the run traced
    /// one, otherwise the whole session (single-tool runs).
    fn completed_tool_secs(&self, tool_name: &str) -> Option<u64> {
        let session = self.activity.as_ref()?;
        let row_secs = session.tasks.get(tool_name).and_then(|row| {
            let started = row.started_at?;
            let completed = row.completed_at?;
            Some(completed.saturating_duration_since(started).as_secs())
        });
        Some(row_secs.unwrap_or_else(|| session.started_at.elapsed().as_secs()))
    }

    fn apply_failed_tool_event(&mut self, state: ToolEventState, tool_name: String, error: String) {
        let failure_context = record_tool_run_failed(
            state.target.as_deref(),
            state.run_id.as_deref(),
            &tool_name,
            &error,
        );
        let result = failed_tool_result(
            state.target.as_deref(),
            state.run_id.as_deref(),
            &tool_name,
            &error,
        );
        self.apply_tool_result(&tool_name, result);
        self.mark_tool_activity_failed(&tool_name, &error);
        self.log_tool_failure(
            &tool_name,
            with_next_step(error.clone(), "tools, options <tool>, or model <n>"),
            state.abort_requested,
        );
        self.set_refused_activity(
            tool_name.clone(),
            "tool failed before producing a usable result",
        );
        self.log_failure_context(failure_context);
        self.abort_pending_chain(&tool_name);
        if self.planning_running_tool.as_deref() == Some(&tool_name) {
            // Dependency-aware fall-through: skip only the tasks that depended
            // on this one; keep running the independent rest of the queue.
            self.fail_planning_task(&tool_name, &error);
        }
    }

    /// Flip the failed tool's Activity DAG row to `Failing` so the progress
    /// pane stops spinning and reflects the error. The tool's producer bails on
    /// failure before emitting a terminal trace step, so we synthesize one here
    /// (mirrors `mark_scan_activity_failed` for the scan pipeline).
    fn mark_tool_activity_failed(&mut self, tool_name: &str, error: &str) {
        let Some(session) = self.activity.as_mut() else {
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

    pub(crate) fn apply_tool_result(&mut self, tool_name: &str, result: serde_json::Value) {
        if let Some(cost_usd) = extract_cost_usd(&result) {
            self.record_cost(cost_usd);
        }
        if matches!(tool_name, "context:build" | "context-lite:index") {
            let _ = self.refresh_context_view();
        }
        self.cache_tool_snapshot(tool_name, &result);
        if tool_name == "module-recommender:recommend" {
            self.apply_model_recommendations(&result);
        }
        let rendered = result
            .get("output")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
            });
        self.log("result", rendered);
    }
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
    let result = serde_json::json!({
        "ok": false,
        "status": "failed",
        "summary": format!("{tool_name} failed"),
        "artifacts": failed_tool_artifacts(target, run_id),
        "warnings": [],
        "errors": [error],
    });
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
