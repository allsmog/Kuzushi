//! Bridges the picker UI to the existing `start_background_tool`
//! machinery. The PlanningPicker hands a topo-sorted queue to this
//! runner; it pops one task at a time and re-arms itself in
//! `advance_planning_queue_after_tool` (called from the post-completion
//! tool-event handler).

use super::dependencies::{topological_order, transitive_dependencies};
use super::failure::{FailedPlanningTask, PendingRetry, RetryAdjustment};
use super::recommend::model_recommended_in_phase;
use super::task_id::PlanningTaskId;
use crate::app::{auth_ready_for_provider, WorkflowPhase};
use crate::{ShellApp, ShellView};
use kuzushi_core::WorkspaceTarget;
use serde_json::{json, Value};
use std::collections::BTreeSet;

impl ShellApp {
    /// Dispatch the head of the planning queue (if any) on `workspace`.
    /// No-op when the queue is empty or another tool is already running.
    pub(crate) fn dispatch_next_planning_task(&mut self, workspace: WorkspaceTarget) {
        if self.tool_running.is_some() {
            return;
        }
        let Some(task) = self.planning_run_queue.pop_front() else {
            self.planning_running_tool = None;
            return;
        };
        let tool_name = task.tool_name();
        let input = self.input_for_planning_task(task);
        self.planning_running_tool = Some(tool_name.to_string());
        self.log(
            "planning",
            format!(
                "running planning step {} ({}/{} remaining)",
                tool_name,
                self.planning_run_queue.len() + 1,
                self.planning_run_queue.len() + 1,
            ),
        );
        self.start_background_tool(
            tool_name.to_string(),
            input,
            workspace,
            "planning queue task in flight",
            self.session_thinking_level.clone(),
        );
    }

    /// Called after every completed background tool. If the completed
    /// tool belongs to our planning queue, advance to the next entry.
    pub(crate) fn advance_planning_queue_after_tool(&mut self, tool_name: &str) {
        let Some(running) = self.planning_running_tool.as_deref() else {
            return;
        };
        if running != tool_name {
            return;
        }
        self.planning_running_tool = None;
        // Refresh the MCP attachment summary: the completed tool may
        // have produced an artifact whose absence was the only reason
        // an MCP wasn't attached.
        self.log_mcp_attachment_plan();
        if self.planning_run_queue.is_empty() {
            self.advance_to_next_phase();
            return;
        }
        let Ok(workspace) = self.current_workspace() else {
            self.log(
                "error",
                "planning queue paused: no active workspace; resume with /planning",
            );
            self.planning_run_queue.clear();
            return;
        };
        self.dispatch_next_planning_task(workspace);
    }

    /// Kick off the one-shot session-model ranking for this engagement. Runs
    /// once (reused across phases), only when a model is configured, and keeps
    /// the current view (the phase picker stays up while it ranks in the
    /// background). No model configured → silently stays deterministic.
    pub(crate) fn request_model_recommendations(&mut self) {
        if self.recommendation_requested
            || self.config.model.is_none()
            || !matches!(self.shell_view, ShellView::PlanningPicker)
        {
            return;
        }
        let Ok(workspace) = self.current_workspace() else {
            return;
        };
        self.recommendation_requested = true;
        // Internal recommender run: suppress both view auto-opens so it doesn't
        // hijack the view, then restore the operator's prefs.
        let auto_open = self.auto_open_activity;
        let auto_open_viz = self.auto_open_viz;
        self.auto_open_activity = false;
        self.auto_open_viz = false;
        self.start_background_tool(
            "module-recommender:recommend".to_string(),
            json!({}),
            workspace,
            "ranking tools for this target",
            None,
        );
        self.auto_open_activity = auto_open;
        self.auto_open_viz = auto_open_viz;
        self.log(
            "phase",
            "ranking tools for this target with the session model…",
        );
    }

    /// Completion hook for the recommender: map its tool picks to planning
    /// tasks, cache them for every phase, and refine the open picker.
    pub(crate) fn apply_model_recommendations(&mut self, result: &Value) {
        let tasks = model_tasks_from_recommendation_result(result);
        if !tasks.is_empty() {
            let count = tasks.len();
            self.model_recommended_tasks = Some(tasks);
            if matches!(self.shell_view, ShellView::PlanningPicker) {
                if let Some(phase) = self.workflow_phase {
                    self.refine_open_picker_with_model(phase);
                }
            }
            self.log(
                "phase",
                format!("session model recommended {count} tool(s) — preselection refined"),
            );
        }
        // If the operator committed a plan while ranking was still in flight,
        // the queue stalled (dispatch was blocked by the recommender). Resume it.
        self.resume_pending_planning_after_recommendation();
    }

    fn resume_pending_planning_after_recommendation(&mut self) {
        if self.planning_run_queue.is_empty()
            || self.planning_running_tool.is_some()
            || self.tool_running.is_some()
        {
            return;
        }
        if let Ok(workspace) = self.current_workspace() {
            self.dispatch_next_planning_task(workspace);
        }
    }

    fn refine_open_picker_with_model(&mut self, phase: WorkflowPhase) {
        let Some(model_tasks) = self.model_recommended_tasks.clone() else {
            return;
        };
        let phase_tasks: BTreeSet<PlanningTaskId> =
            self.planning_tasks.iter().map(|row| row.id).collect();
        for task in model_recommended_in_phase(&model_tasks, &self.planning_tasks, phase) {
            self.planning_selected.insert(task);
            for dep in transitive_dependencies(task) {
                if phase_tasks.contains(&dep) {
                    self.planning_selected.insert(dep);
                }
            }
        }
    }

    /// A queued planning task failed. Record it (with any auto-retry hint),
    /// drop the queued tasks that transitively depended on it, and keep running
    /// the independent remainder — failure of one task no longer kills the run.
    pub(crate) fn fail_planning_task(&mut self, tool_name: &str, error: &str) {
        self.planning_running_tool = None;
        if let Some(task) = planning_task_for_tool(tool_name) {
            let skipped = self.skip_queued_dependents(task);
            self.log_skipped_dependents(task, &skipped);
            self.planning_failed.push(FailedPlanningTask {
                task,
                error: first_line(error),
                adjustment: retry_adjustment_from_error(error),
                blocked: skipped,
            });
        }
        self.resume_or_advance_planning_queue();
    }

    /// Remove from the queue every task that transitively depends on `failed`.
    fn skip_queued_dependents(&mut self, failed: PlanningTaskId) -> Vec<PlanningTaskId> {
        let skipped: Vec<PlanningTaskId> = self
            .planning_run_queue
            .iter()
            .copied()
            .filter(|task| transitive_dependencies(*task).contains(&failed))
            .collect();
        self.planning_run_queue
            .retain(|task| !skipped.contains(task));
        skipped
    }

    fn log_skipped_dependents(&mut self, failed: PlanningTaskId, skipped: &[PlanningTaskId]) {
        if skipped.is_empty() {
            self.log(
                "phase",
                format!(
                    "{} failed — no queued task depended on it; continuing",
                    failed.tool_name()
                ),
            );
            return;
        }
        let names = skipped
            .iter()
            .map(|task| task.tool_name())
            .collect::<Vec<_>>()
            .join(", ");
        self.log(
            "phase",
            format!(
                "{} failed — skipping dependents: {names}",
                failed.tool_name()
            ),
        );
    }

    fn resume_or_advance_planning_queue(&mut self) {
        if self.planning_run_queue.is_empty() {
            self.advance_to_next_phase();
            return;
        }
        match self.current_workspace() {
            Ok(workspace) => self.dispatch_next_planning_task(workspace),
            Err(_) => {
                self.planning_run_queue.clear();
                self.log("error", "planning queue paused: no active workspace");
            }
        }
    }

    /// After a phase's queue drains (or the operator skips it), open the next
    /// phase's picker — 組 → 崩 → 作 → 掛 — or finish the engagement after 掛 KAKE.
    pub(crate) fn advance_to_next_phase(&mut self) {
        match self.workflow_phase.and_then(|phase| phase.next()) {
            Some(next) => self.open_phase_picker(next),
            None => self.finish_engagement(),
        }
    }

    /// End of the engagement (past 掛 KAKE). When tasks failed, offer a yes/no
    /// retry gate (auto-adjusted where the cause is known); otherwise fall
    /// through to next-step recommendations.
    fn finish_engagement(&mut self) {
        self.workflow_phase = None;
        // The phase walker covered the startup MCP-plan line; re-emit it now
        // that completed phases may have built new attachable artifacts.
        self.log_mcp_attachment_plan();
        if self.planning_failed.is_empty() {
            self.finish_planning_with_recommendations();
            return;
        }
        self.open_retry_gate();
    }

    fn open_retry_gate(&mut self) {
        let tasks = self.planning_failed.clone();
        let count = tasks.len();
        self.advisory.pending_retry = Some(PendingRetry { tasks });
        self.log(
            "phase",
            format!("{count} task(s) failed — retry? [y] retry · [n] skip"),
        );
    }

    /// Operator accepted the retry gate: re-queue every failed task (with its
    /// auto-adjustment) plus the dependents that were skipped, then run them.
    pub(crate) fn retry_failed_tasks(&mut self) {
        let Some(pending) = self.advisory.pending_retry.take() else {
            return;
        };
        self.planning_failed.clear();
        self.planning_adjustments.clear();
        let mut tasks: BTreeSet<PlanningTaskId> = BTreeSet::new();
        for item in &pending.tasks {
            tasks.insert(item.task);
            tasks.extend(item.blocked.iter().copied());
            if let Some(adjustment) = &item.adjustment {
                self.planning_adjustments
                    .insert(item.task, adjustment.clone());
            }
        }
        let plan = topological_order(&tasks);
        let labels = plan
            .iter()
            .map(|task| task.tool_name())
            .collect::<Vec<_>>()
            .join(" → ");
        self.log(
            "phase",
            format!("retrying {} task(s): {labels}", plan.len()),
        );
        self.planning_run_queue = plan.into_iter().collect();
        match self.current_workspace() {
            Ok(workspace) => {
                self.shell_view = ShellView::Catalog;
                self.dispatch_next_planning_task(workspace);
            }
            Err(_) => {
                self.planning_run_queue.clear();
                self.log("error", "cannot retry without an active workspace");
            }
        }
    }

    /// Operator declined the retry gate: drop the failures and move on.
    pub(crate) fn decline_retry(&mut self) {
        self.advisory.pending_retry = None;
        self.planning_failed.clear();
        self.planning_adjustments.clear();
        self.log("phase", "retry skipped");
        self.finish_planning_with_recommendations();
    }

    /// Tool input for a planning task, with any retry adjustment applied (e.g.
    /// a larger `heapMb` after a joern OOM).
    fn input_for_planning_task(&self, task: PlanningTaskId) -> Value {
        let mut input = planning_task_input(task);
        if let Some(RetryAdjustment::RaiseHeap { heap_mb }) = self.planning_adjustments.get(&task) {
            if let Some(object) = input.as_object_mut() {
                object.insert("heapMb".to_string(), json!(heap_mb));
            }
        }
        input
    }

    /// Planning is done. Rather than strand the operator on a finished, empty
    /// Activity DAG, auto-run the deterministic module recommender and land on
    /// the Recommend view so they are shown concrete next steps. The recommender
    /// dispatch deliberately doesn't touch `planning_running_tool`, so its own
    /// completion won't re-enter this path.
    fn finish_planning_with_recommendations(&mut self) {
        self.log("planning", "planning complete");
        let Ok(workspace) = self.current_workspace() else {
            self.log(
                "recommend",
                "planning complete — run `recommend` for suggested next modules",
            );
            return;
        };
        // Suppress both view auto-opens so we land on Recommend, not the empty
        // Activity view (or a stale gallery page) the operator just finished with.
        let auto_open = self.auto_open_activity;
        let auto_open_viz = self.auto_open_viz;
        self.auto_open_activity = false;
        self.auto_open_viz = false;
        self.start_background_tool(
            "module-recommender:recommend".to_string(),
            json!({}),
            workspace,
            "ranking next modules",
            None,
        );
        self.auto_open_activity = auto_open;
        self.auto_open_viz = auto_open_viz;
        self.shell_view = ShellView::Recommend;
        self.log("recommend", "ranking modules for your next move…");
    }

    /// Whether a chosen model has all the credentials it needs to run.
    /// Used by the auth picker to decide whether to fall through to the
    /// planning view or stay put until the operator finishes auth.
    #[allow(dead_code)] // reserved for the auth-picker fall-through path
    pub(crate) fn chosen_provider_auth_ready(&self) -> bool {
        let Some(provider) = self
            .config
            .model
            .as_deref()
            .and_then(|model| model.split(':').next())
        else {
            return false;
        };
        auth_ready_for_provider(provider)
    }
}

/// Resolve a tool name back to its planning task. STRIDE/PASTA share a tool
/// name; the first match (STRIDE) is fine for failure bookkeeping.
fn planning_task_for_tool(tool_name: &str) -> Option<PlanningTaskId> {
    PlanningTaskId::ALL
        .iter()
        .copied()
        .find(|task| task.tool_name() == tool_name)
}

/// Parse the `[retry:raise-heap:<mb>]` hint a tool embeds in its error so the
/// retry gate can offer an auto-adjusted re-run.
fn retry_adjustment_from_error(error: &str) -> Option<RetryAdjustment> {
    const MARKER: &str = "[retry:raise-heap:";
    let start = error.find(MARKER)? + MARKER.len();
    let rest = &error[start..];
    let end = rest.find(']')?;
    let heap_mb: u64 = rest[..end].trim().parse().ok()?;
    Some(RetryAdjustment::RaiseHeap { heap_mb })
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or(text).trim().to_string()
}

/// Map the recommender result's tool list to planning tasks (ignoring tools
/// that aren't part of the phase taxonomy).
fn model_tasks_from_recommendation_result(result: &Value) -> BTreeSet<PlanningTaskId> {
    let recommendations = result
        .pointer("/data/recommendations")
        .or_else(|| result.pointer("/data/recommendationReport/recommendations"))
        .and_then(Value::as_array);
    let Some(recommendations) = recommendations else {
        return BTreeSet::new();
    };
    recommendations
        .iter()
        .filter_map(|rec| rec.get("tool").and_then(Value::as_str))
        .filter_map(planning_task_for_tool)
        .collect()
}

fn planning_task_input(task: PlanningTaskId) -> Value {
    match task {
        PlanningTaskId::BuildPastaThreatModel => json!({
            "methodology": "pasta",
            "outputDir": ".kuzushi/threat-model-pasta",
        }),
        PlanningTaskId::BuildStrideThreatModel => json!({
            "methodology": "stride",
        }),
        _ => json!({}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;
    use PlanningTaskId::*;

    #[test]
    fn retry_hint_parses_raise_heap_token() {
        assert_eq!(
            retry_adjustment_from_error("java heap OOM ... [retry:raise-heap:12288]"),
            Some(RetryAdjustment::RaiseHeap { heap_mb: 12288 })
        );
        assert_eq!(retry_adjustment_from_error("a plain parse error"), None);
    }

    #[test]
    fn model_recommendation_result_maps_tools_to_phase_tasks() {
        // Mirrors the recommender's completed_output_result envelope: report
        // under `data`, recommendations carrying tool names. Tools outside the
        // phase taxonomy (e.g. sast:scan) are dropped.
        let result = json!({
            "data": {
                "recommendations": [
                    { "tool": "secret-scan:scan" },
                    { "tool": "sast:scan" },
                    { "tool": "semgrep:scan" }
                ]
            }
        });
        let tasks = model_tasks_from_recommendation_result(&result);
        assert!(tasks.contains(&ScanSecrets));
        assert!(tasks.contains(&ScanSemgrep));
        // sast:scan has no planning task and is dropped.
        assert_eq!(tasks.len(), 2);
    }

    #[test]
    fn skipping_drops_dependents_but_keeps_independents() {
        let mut app = ShellApp::new(V2Config::default(), None);
        // Hunt-phase queue: taint depends on the CPG, secret-scan does not.
        app.planning_run_queue = [HuntTaint, ScanSecrets].into_iter().collect();
        let skipped = app.skip_queued_dependents(BuildCodePropertyGraph);
        assert_eq!(skipped, vec![HuntTaint]);
        assert!(app.planning_run_queue.contains(&ScanSecrets));
        assert!(!app.planning_run_queue.contains(&HuntTaint));
    }
}
