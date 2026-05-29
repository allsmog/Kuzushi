//! Bridges the picker UI to the existing `start_background_tool`
//! machinery. The PlanningPicker hands a topo-sorted queue to this
//! runner; it pops one task at a time and re-arms itself in
//! `advance_planning_queue_after_tool` (called from the post-completion
//! tool-event handler).

use super::task_id::PlanningTaskId;
use crate::app::auth_ready_for_provider;
use crate::{ShellApp, ShellView};
use kuzushi_core::WorkspaceTarget;
use serde_json::{json, Value};

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
        let input = planning_task_input(task);
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
            self.finish_planning_with_recommendations();
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
        // Suppress the activity auto-open flip so we land on Recommend, not the
        // empty Activity view the operator just finished with.
        let auto_open = self.auto_open_activity;
        self.auto_open_activity = false;
        self.start_background_tool(
            "module-recommender:recommend".to_string(),
            json!({}),
            workspace,
            "ranking next modules",
            None,
        );
        self.auto_open_activity = auto_open;
        self.shell_view = ShellView::Recommend;
        self.log("recommend", "ranking modules for your next move…");
    }

    /// Cancel any in-flight planning queue. Does NOT abort the
    /// currently-running tool (call `request_tool_abort` for that).
    pub(crate) fn cancel_planning_queue(&mut self) {
        if self.planning_run_queue.is_empty() && self.planning_running_tool.is_none() {
            return;
        }
        let pending = self.planning_run_queue.len();
        self.planning_run_queue.clear();
        self.planning_running_tool = None;
        self.log(
            "planning",
            format!("planning queue cancelled — {pending} step(s) skipped"),
        );
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
