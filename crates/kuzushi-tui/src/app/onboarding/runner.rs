//! Bridges the picker UI to the existing `start_background_tool`
//! machinery. The PlanningPicker hands a topo-sorted queue to this
//! runner; it pops one task at a time and re-arms itself in
//! `advance_planning_queue_after_tool` (called from the post-completion
//! tool-event handler).

use super::dependencies::{topological_order, transitive_dependencies};
use super::failure::{FailedPlanningTask, PendingRetry, RetryAdjustment};
use super::planning_task_explicit_input;
use super::recommend::model_recommended_in_phase;
use super::task_id::PlanningTaskId;
use crate::app::WorkflowPhase;
use crate::{ShellApp, ShellView};
use anyhow::Result;
use kuzushi_core::{
    Finding, NestedProjectKind, ToolExecutionContext, TriageVerdict, WorkspaceTarget,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct PlanningRunStep {
    pub(crate) task: PlanningTaskId,
    pub(crate) tool_name: String,
    pub(crate) input: Value,
}

impl ShellApp {
    /// Dispatch the head of the planning queue (if any) on `workspace`.
    /// No-op when the queue is empty or another tool is already running.
    pub(crate) fn dispatch_next_planning_task(&mut self, workspace: WorkspaceTarget) {
        if self.tool_running.is_some() {
            self.log_planning_queue_stalled();
            return;
        }
        let Some(step) = self.next_planning_run_step(&workspace) else {
            self.engagement.clear_running_tool();
            return;
        };
        self.dispatch_planning_run_step(step, workspace);
    }

    fn next_planning_run_step(&mut self, workspace: &WorkspaceTarget) -> Option<PlanningRunStep> {
        loop {
            if let Some(step) = self.engagement.pop_expanded_step() {
                return Some(step);
            }
            let task = self.engagement.pop_queued_task()?;
            match self.expand_planning_task(task, workspace) {
                Ok(steps) if steps.is_empty() => continue,
                Ok(steps) => self.engagement.replace_expanded_steps(steps),
                Err(error) => {
                    self.log(
                        "error",
                        format!("{} input invalid: {error:#}", task.tool_name()),
                    );
                    self.fail_planning_task(task.tool_name(), &format!("{error:#}"));
                    return None;
                }
            }
        }
    }

    fn dispatch_planning_run_step(&mut self, step: PlanningRunStep, workspace: WorkspaceTarget) {
        if let Some(error) =
            self.langgraph_background_tool_launch_blocker(&step.tool_name, &step.input)
        {
            self.log("error", error.clone());
            self.fail_planning_task(&step.tool_name, &error);
            return;
        }
        self.engagement.set_running_tool(step.tool_name.clone());
        self.log(
            "planning",
            format!(
                "running planning step {} · {} queued after it",
                step.tool_name,
                self.pending_planning_step_count(),
            ),
        );
        self.start_background_tool(
            step.tool_name,
            step.input,
            workspace,
            "planning queue task in flight",
            self.session_thinking_level.clone(),
        );
    }

    fn expand_planning_task(
        &mut self,
        task: PlanningTaskId,
        workspace: &WorkspaceTarget,
    ) -> Result<Vec<PlanningRunStep>> {
        match task {
            PlanningTaskId::VerifyFindings => self.expand_finding_batch(
                task,
                eligible_verify_fingerprints(&self.findings),
                "no triaged findings ready for verification",
                workspace,
            ),
            PlanningTaskId::PatchFindings => self.expand_finding_batch(
                task,
                eligible_patch_fingerprints(&self.findings),
                "no confirmed true-positive findings ready for patching",
                workspace,
            ),
            PlanningTaskId::ReverseEngineerBinary => {
                self.expand_reverse_engineering_task(task, workspace)
            }
            _ => self.expand_single_planning_task(task, workspace),
        }
    }

    fn expand_finding_batch(
        &mut self,
        task: PlanningTaskId,
        fingerprints: Vec<String>,
        empty_reason: &str,
        workspace: &WorkspaceTarget,
    ) -> Result<Vec<PlanningRunStep>> {
        if fingerprints.is_empty() {
            self.log(
                "planning",
                format!("{} skipped — {empty_reason}", task.tool_name()),
            );
            return Ok(Vec::new());
        }
        fingerprints
            .into_iter()
            .map(|fingerprint| {
                self.step_with_extra_input(task, json!({ "fingerprint": fingerprint }), workspace)
            })
            .collect()
    }

    fn expand_reverse_engineering_task(
        &mut self,
        task: PlanningTaskId,
        workspace: &WorkspaceTarget,
    ) -> Result<Vec<PlanningRunStep>> {
        let Some(binary) = reverse_binary_for_target(workspace.root()) else {
            self.log(
                "planning",
                format!(
                    "{} skipped — no binary artifact found under {}",
                    task.tool_name(),
                    workspace.root().display()
                ),
            );
            return Ok(Vec::new());
        };
        self.step_with_extra_input(
            task,
            json!({ "binary": binary.display().to_string() }),
            workspace,
        )
        .map(|step| vec![step])
    }

    fn expand_single_planning_task(
        &self,
        task: PlanningTaskId,
        workspace: &WorkspaceTarget,
    ) -> Result<Vec<PlanningRunStep>> {
        self.input_for_planning_task(task)
            .and_then(|input| {
                self.dispatch_input_for_planning_task(task.tool_name(), input, workspace)
            })
            .map(|input| {
                vec![PlanningRunStep {
                    task,
                    tool_name: task.tool_name().to_string(),
                    input,
                }]
            })
    }

    fn step_with_extra_input(
        &self,
        task: PlanningTaskId,
        extra: Value,
        workspace: &WorkspaceTarget,
    ) -> Result<PlanningRunStep> {
        let input = self.input_for_planning_task_with_extra(task, extra)?;
        let input = self.dispatch_input_for_planning_task(task.tool_name(), input, workspace)?;
        Ok(PlanningRunStep {
            task,
            tool_name: task.tool_name().to_string(),
            input,
        })
    }

    fn pending_planning_step_count(&self) -> usize {
        self.engagement.pending_planning_step_count()
    }

    fn planning_queues_empty(&self) -> bool {
        self.engagement.planning_queues_empty()
    }

    /// The queue cannot start while another tool holds the single background
    /// slot (e.g. the session-model recommender). The operator just confirmed
    /// a plan — without this line they would silently watch an unrelated tool
    /// run and never learn why their plan hasn't started.
    fn log_planning_queue_stalled(&mut self) {
        let queued = self.pending_planning_step_count();
        if queued == 0 {
            return;
        }
        let running = self.tool_running.clone().unwrap_or_default();
        self.log(
            "planning",
            format!("plan queued ({queued} step(s)) — waiting for {running} to finish first",),
        );
    }

    /// Called after every completed background tool. If the completed
    /// tool belongs to our planning queue, advance to the next entry.
    pub(crate) fn advance_planning_queue_after_tool(&mut self, tool_name: &str) {
        let Some(running) = self.engagement.running_tool() else {
            return;
        };
        if running != tool_name {
            return;
        }
        self.engagement.clear_running_tool();
        // Refresh the MCP attachment summary: the completed tool may
        // have produced an artifact whose absence was the only reason
        // an MCP wasn't attached.
        self.log_mcp_attachment_plan();
        if self.planning_queues_empty() {
            self.advance_to_next_phase();
            return;
        }
        let Ok(workspace) = self.current_workspace() else {
            self.log(
                "error",
                "planning queue paused: no active workspace; resume with /planning",
            );
            self.engagement.clear_planning_queue();
            return;
        };
        self.dispatch_next_planning_task(workspace);
    }

    /// Steps of a confirmed plan waiting behind a non-plan tool. Zero while
    /// the plan itself is executing or when nothing is queued.
    pub(crate) fn stalled_planning_steps(&self) -> usize {
        if self.engagement.has_running_tool() {
            return 0;
        }
        self.pending_planning_step_count()
    }

    /// Whether `name` is the shell-initiated background tool (vs an
    /// operator-triggered run).
    pub(crate) fn tool_is_ambient(&self, name: &str) -> bool {
        self.ambient_tool.as_deref() == Some(name)
    }

    /// Completion hook for the recommender: map its tool picks to planning
    /// tasks, cache them for every phase, and refine the open picker.
    pub(crate) fn apply_model_recommendations(&mut self, result: &Value) {
        let tasks = model_tasks_from_recommendation_result(result);
        if !tasks.is_empty() {
            let count = tasks.len();
            self.engagement.set_model_recommendations(tasks);
            if matches!(self.shell_view, ShellView::PlanningPicker) {
                if let Some(phase) = self.engagement.current_phase() {
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
        if self.planning_queues_empty()
            || self.engagement.has_running_tool()
            || self.tool_running.is_some()
        {
            return;
        }
        if let Ok(workspace) = self.current_workspace() {
            self.dispatch_next_planning_task(workspace);
        }
    }

    fn refine_open_picker_with_model(&mut self, phase: WorkflowPhase) {
        let Some(model_tasks) = self.engagement.model_recommendations_cloned() else {
            return;
        };
        let phase_tasks: BTreeSet<PlanningTaskId> = self
            .planning_picker_route
            .tasks()
            .iter()
            .map(|row| row.id)
            .collect();
        for task in
            model_recommended_in_phase(&model_tasks, self.planning_picker_route.tasks(), phase)
        {
            self.planning_picker_route.selected_mut().insert(task);
            for dep in transitive_dependencies(task) {
                if phase_tasks.contains(&dep) {
                    self.planning_picker_route.selected_mut().insert(dep);
                }
            }
        }
    }

    /// A queued planning task failed. Record it (with any auto-retry hint),
    /// drop the queued tasks that transitively depended on it, and keep running
    /// the independent remainder — failure of one task no longer kills the run.
    pub(crate) fn fail_planning_task(&mut self, tool_name: &str, error: &str) {
        self.engagement.clear_running_tool();
        if let Some(task) = planning_task_for_tool(tool_name) {
            let skipped = self.skip_queued_dependents(task);
            self.log_skipped_dependents(task, &skipped);
            self.engagement.record_failed_task(FailedPlanningTask {
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
        self.engagement
            .remove_queued_tasks_where(|task| transitive_dependencies(task).contains(&failed))
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
        if self.planning_queues_empty() {
            self.advance_to_next_phase();
            return;
        }
        match self.current_workspace() {
            Ok(workspace) => self.dispatch_next_planning_task(workspace),
            Err(_) => {
                self.engagement.clear_planning_queue();
                self.log("error", "planning queue paused: no active workspace");
            }
        }
    }

    /// After a phase's queue drains (or the operator skips it), open the next
    /// phase's picker — 組 → 崩 → 作 → 掛 — or finish the engagement after 掛 KAKE.
    pub(crate) fn advance_to_next_phase(&mut self) {
        let completed = self.engagement.current_phase();
        self.maybe_refresh_recommendations_after_map(completed);
        match completed.and_then(|phase| phase.next()) {
            Some(next) => self.open_or_announce_next_phase(next),
            None => self.finish_engagement(),
        }
    }

    fn maybe_refresh_recommendations_after_map(&mut self, completed: Option<WorkflowPhase>) {
        if !self.should_refresh_recommendations_after_map(completed) {
            return;
        }
        let Ok(workspace) = self.current_workspace() else {
            return;
        };
        self.log("recommend", map_recommendation_notice(workspace.root()));
        if !crate::ui_view_models::recommendation_artifact_needs_refresh(self) {
            return;
        }
        self.start_deterministic_recommender(workspace);
    }

    fn should_refresh_recommendations_after_map(&self, completed: Option<WorkflowPhase>) -> bool {
        completed == Some(WorkflowPhase::Map)
            && !self
                .engagement
                .skipped_phases()
                .contains(&WorkflowPhase::Map)
            && self.tool_running.is_none()
            && self.target.is_some()
    }

    fn start_deterministic_recommender(&mut self, workspace: WorkspaceTarget) {
        let input = json!({ "useModelRanking": false });
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
        };
        let prepared = match self.registry.prepare_tool_input_for_dispatch(
            "module-recommender:recommend",
            input,
            &ctx,
            Some(&self.option_store),
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.log("error", format!("recommendation input invalid: {error}"));
                return;
            }
        };
        let previous_auto_open = self.auto_open_activity;
        self.auto_open_activity = false;
        self.start_background_tool(
            "module-recommender:recommend".to_string(),
            prepared,
            workspace,
            "deterministic module recommendations in flight",
            None,
        );
        self.auto_open_activity = previous_auto_open;
    }

    fn open_or_announce_next_phase(&mut self, next: WorkflowPhase) {
        if self.should_auto_open_next_phase() {
            self.open_phase_picker(next);
            return;
        }
        self.engagement.set_phase(next);
        self.set_success_notice(
            "phase",
            format!("{} ready — type `next` to continue", next.label()),
        );
    }

    fn should_auto_open_next_phase(&self) -> bool {
        matches!(
            self.shell_view,
            ShellView::Activity | ShellView::PlanningPicker
        )
    }

    /// End of the engagement (past 掛 KAKE). When tasks failed, offer a yes/no
    /// retry gate (auto-adjusted where the cause is known); otherwise return to
    /// the Workbench cockpit.
    fn finish_engagement(&mut self) {
        self.engagement.clear_phase();
        // The phase walker covered the startup MCP-plan line; re-emit it now
        // that completed phases may have built new attachable artifacts.
        self.log_mcp_attachment_plan();
        if !self.engagement.has_failed_tasks() {
            self.finish_planning();
            return;
        }
        self.open_retry_gate();
    }

    fn open_retry_gate(&mut self) {
        let tasks = self.engagement.failed_tasks_cloned();
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
        self.reset_retry_state();
        let tasks = self.retryable_tasks_from_failures(&pending.tasks);
        if tasks.is_empty() {
            self.log("phase", "no retryable failed tasks remain");
            self.finish_planning();
            return;
        }
        let plan = topological_order(&tasks);
        self.log_retry_plan(&plan);
        self.queue_retry_plan(plan);
        self.dispatch_retry_plan();
    }

    fn reset_retry_state(&mut self) {
        self.engagement.clear_failures_and_adjustments();
    }

    fn retryable_tasks_from_failures(
        &mut self,
        failures: &[FailedPlanningTask],
    ) -> BTreeSet<PlanningTaskId> {
        let mut tasks: BTreeSet<PlanningTaskId> = BTreeSet::new();
        for item in failures {
            self.add_retryable_task(item, &mut tasks);
        }
        tasks
    }

    fn add_retryable_task(
        &mut self,
        item: &FailedPlanningTask,
        tasks: &mut BTreeSet<PlanningTaskId>,
    ) {
        if failed_task_is_structurally_unsatisfiable(item) {
            self.log_non_retryable_task(item);
            return;
        }
        tasks.insert(item.task);
        tasks.extend(item.blocked.iter().copied());
        self.store_retry_adjustment(item);
    }

    fn log_non_retryable_task(&mut self, item: &FailedPlanningTask) {
        self.log(
            "phase",
            format!("not retrying {} — {}", item.task.tool_name(), item.error),
        );
    }

    fn store_retry_adjustment(&mut self, item: &FailedPlanningTask) {
        if let Some(adjustment) = &item.adjustment {
            self.engagement
                .insert_retry_adjustment(item.task, adjustment.clone());
        }
    }

    fn log_retry_plan(&mut self, plan: &[PlanningTaskId]) {
        let labels = plan
            .iter()
            .map(|task| task.tool_name())
            .collect::<Vec<_>>()
            .join(" → ");
        self.log(
            "phase",
            format!("retrying {} task(s): {labels}", plan.len()),
        );
    }

    fn queue_retry_plan(&mut self, plan: Vec<PlanningTaskId>) {
        self.engagement.queue_plan(plan);
    }

    fn dispatch_retry_plan(&mut self) {
        match self.current_workspace() {
            Ok(workspace) => {
                self.shell_view = ShellView::Catalog;
                self.dispatch_next_planning_task(workspace);
            }
            Err(_) => {
                self.engagement.clear_planning_queue();
                self.log("error", "cannot retry without an active workspace");
            }
        }
    }

    /// Operator declined the retry gate: drop the failures and move on.
    pub(crate) fn decline_retry(&mut self) {
        self.advisory.pending_retry = None;
        self.engagement.clear_failures_and_adjustments();
        self.engagement.clear_planning_queue();
        self.log("phase", "retry skipped");
        self.finish_planning();
    }

    /// Tool input for a planning task, with any retry adjustment applied (e.g.
    /// a larger `heapMb` after a joern OOM).
    fn input_for_planning_task(&self, task: PlanningTaskId) -> Result<Value> {
        let mut input = self.input_for_planning_task_with_options(task)?;
        if let Some(RetryAdjustment::RaiseHeap { heap_mb }) = self.engagement.retry_adjustment(task)
        {
            if let Some(object) = input.as_object_mut() {
                object.insert("heapMb".to_string(), json!(heap_mb));
            }
        }
        Ok(input)
    }

    fn input_for_planning_task_with_extra(
        &self,
        task: PlanningTaskId,
        extra: Value,
    ) -> Result<Value> {
        let mut input = planning_task_explicit_input(task, self.engagement.option_overrides());
        merge_input_object(&mut input, extra);
        if let Some(RetryAdjustment::RaiseHeap { heap_mb }) = self.engagement.retry_adjustment(task)
        {
            if let Some(object) = input.as_object_mut() {
                object.insert("heapMb".to_string(), json!(heap_mb));
            }
        }
        Ok(input)
    }

    fn dispatch_input_for_planning_task(
        &self,
        tool_name: &str,
        input: Value,
        workspace: &WorkspaceTarget,
    ) -> Result<Value> {
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
        };
        self.registry.prepare_tool_input_for_dispatch(
            tool_name,
            input,
            &ctx,
            Some(&self.option_store),
        )
    }

    /// Planning is done. Return to the Workbench cockpit and leave the module
    /// recommender as an explicit operator action.
    fn finish_planning(&mut self) {
        self.engagement.clear_planning_queue();
        self.log("planning", "planning complete");
        self.open_workbench(crate::app::WorkbenchPane::Findings);
        self.log(
            "recommend",
            "run `recommend` when you want suggested next modules",
        );
    }
}

fn map_recommendation_notice(root: &Path) -> String {
    let labels = product_boundary_labels(root);
    if labels.is_empty() {
        return "map complete — running deterministic module recommendations".to_string();
    }
    let preview = boundary_preview(&labels);
    format!(
        "map complete — detected {} product boundaries: {} — `recommend` to inspect module suggestions",
        labels.len(),
        preview
    )
}

fn boundary_preview(labels: &[String]) -> String {
    let mut preview = labels.iter().take(5).cloned().collect::<Vec<_>>();
    if labels.len() > preview.len() {
        preview.push(format!("+{} more", labels.len() - preview.len()));
    }
    preview.join(" ")
}

fn product_boundary_labels(root: &Path) -> Vec<String> {
    let tree = match kuzushi_core::load_nested_project_scopes(root) {
        Ok(Some(tree)) => tree,
        _ => kuzushi_core::discover_nested_project_scopes(root),
    };
    tree.non_root_scopes()
        .filter(|scope| product_boundary_kind(scope.kind))
        .map(|scope| format!("{}/", scope.display_label().trim_end_matches('/')))
        .collect()
}

fn product_boundary_kind(kind: NestedProjectKind) -> bool {
    matches!(
        kind,
        NestedProjectKind::PackageRoot
            | NestedProjectKind::Submodule
            | NestedProjectKind::EntrypointCluster
    )
}

fn merge_input_object(input: &mut Value, extra: Value) {
    let (Some(input), Some(extra)) = (input.as_object_mut(), extra.as_object()) else {
        return;
    };
    input.extend(
        extra
            .iter()
            .map(|(key, value)| (key.clone(), value.clone())),
    );
}

fn eligible_verify_fingerprints(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .filter(|finding| triage_allows_verification(finding))
        .map(|finding| finding.fingerprint.clone())
        .collect()
}

fn triage_allows_verification(finding: &Finding) -> bool {
    finding.triage.as_ref().is_some_and(|triage| {
        matches!(
            triage.verdict,
            TriageVerdict::TruePositive | TriageVerdict::NeedsReview
        )
    })
}

fn eligible_patch_fingerprints(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .filter(|finding| triage_confirms_patchable(finding))
        .map(|finding| finding.fingerprint.clone())
        .collect()
}

fn triage_confirms_patchable(finding: &Finding) -> bool {
    finding
        .triage
        .as_ref()
        .is_some_and(|triage| triage.verdict == TriageVerdict::TruePositive)
}

fn reverse_binary_for_target(root: &Path) -> Option<PathBuf> {
    if root.is_file() {
        return Some(root.to_path_buf());
    }
    let dex = root.join("classes.dex");
    if dex.is_file() {
        return Some(dex);
    }
    first_reverse_engineering_file(root)
}

fn first_reverse_engineering_file(root: &Path) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    let mut budget = 20_000usize;
    while budget > 0 {
        let dir = stack.pop()?;
        if let Some(path) = reverse_engineering_file_in_dir(&dir, &mut stack, &mut budget) {
            return Some(path);
        }
    }
    None
}

fn reverse_engineering_file_in_dir(
    dir: &Path,
    stack: &mut Vec<PathBuf>,
    budget: &mut usize,
) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        if !consume_reverse_file_budget(budget) {
            break;
        }
        if let Some(path) = reverse_engineering_file_candidate(entry.path(), stack) {
            return Some(path);
        }
    }
    None
}

fn consume_reverse_file_budget(budget: &mut usize) -> bool {
    if *budget == 0 {
        return false;
    }
    *budget -= 1;
    true
}

fn reverse_engineering_file_candidate(path: PathBuf, stack: &mut Vec<PathBuf>) -> Option<PathBuf> {
    if path.is_dir() {
        stack.push(path);
        return None;
    }
    is_reverse_engineering_file(&path).then_some(path)
}

fn is_reverse_engineering_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "so" | "dylib" | "dll" | "exe" | "bin" | "elf" | "apk"
            )
        })
        .unwrap_or(false)
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

fn failed_task_is_structurally_unsatisfiable(item: &FailedPlanningTask) -> bool {
    if item.adjustment.is_some() {
        return false;
    }
    let error = item.error.to_ascii_lowercase();
    structurally_unsatisfiable_error(&error)
}

fn structurally_unsatisfiable_error(error: &str) -> bool {
    error.contains("requires a fingerprint")
        || error.contains("fingerprint is required")
        || error.contains("binary is required")
        || error.contains("requires a clangd-compatible compile_commands.json")
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

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Severity, TriageOutcome, V2Config};
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
        app.engagement.queue_plan(vec![HuntTaint, ScanSecrets]);
        let skipped = app.skip_queued_dependents(BuildCodePropertyGraph);
        assert_eq!(skipped, vec![HuntTaint]);
        assert!(app.engagement.queued_task_contains(ScanSecrets));
        assert!(!app.engagement.queued_task_contains(HuntTaint));
    }

    #[test]
    fn verify_planning_task_expands_per_triaged_finding() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let mut app = ShellApp::new(config, Some(&workspace));
        let verify_me = finding_with_triage("demo.sql", TriageVerdict::NeedsReview);
        let skip_me = finding_without_triage("demo.untriaged");
        let expected = verify_me.fingerprint.clone();
        app.findings = vec![verify_me, skip_me];

        let steps = app
            .expand_planning_task(VerifyFindings, &workspace)
            .unwrap();

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tool_name, "verify:finding");
        assert_eq!(steps[0].input["fingerprint"], expected);
    }

    #[test]
    fn patch_planning_task_expands_only_confirmed_true_positives() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        let mut app = ShellApp::new(config, Some(&workspace));
        let patch_me = finding_with_triage("demo.tp", TriageVerdict::TruePositive);
        let skip_me = finding_with_triage("demo.review", TriageVerdict::NeedsReview);
        let expected = patch_me.fingerprint.clone();
        app.findings = vec![patch_me, skip_me];

        let steps = app.expand_planning_task(PatchFindings, &workspace).unwrap();

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tool_name, "patch:finding");
        assert_eq!(steps[0].input["fingerprint"], expected);
    }

    #[test]
    fn reverse_engineering_planning_task_autofills_binary_from_target() {
        let tmp = tempfile::tempdir().unwrap();
        let binary = tmp.path().join("classes.dex");
        std::fs::write(&binary, b"dex\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        let steps = app
            .expand_planning_task(ReverseEngineerBinary, &workspace)
            .unwrap();

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tool_name, "pwn:reverse");
        let expected_binary = std::fs::canonicalize(binary).unwrap();
        assert_eq!(
            steps[0].input["binary"],
            expected_binary.display().to_string()
        );
    }

    #[test]
    fn retry_filter_rejects_structurally_unsatisfiable_required_input() {
        let failed = FailedPlanningTask {
            task: VerifyFindings,
            error: "verify:finding requires a fingerprint".to_string(),
            adjustment: None,
            blocked: vec![PatchFindings],
        };
        assert!(failed_task_is_structurally_unsatisfiable(&failed));
    }

    fn finding_with_triage(rule: &str, verdict: TriageVerdict) -> Finding {
        let mut finding = finding_without_triage(rule);
        finding.triage = Some(TriageOutcome {
            verdict,
            confidence: 0.8,
            rationale: "test".to_string(),
            ..Default::default()
        });
        finding
    }

    fn finding_without_triage(rule: &str) -> Finding {
        Finding::new_semgrep(rule, "src/app.ts", 1, Some(1), Severity::High, rule)
    }
}
