//! Bridges the picker UI to the existing `start_background_tool`
//! machinery. The PlanningPicker hands a topo-sorted queue to this
//! runner; it pops one task at a time and re-arms itself in
//! `advance_planning_queue_after_tool` (called from the post-completion
//! tool-event handler).

use super::dependencies::{topological_order, transitive_dependencies};
use super::failure::{FailedPlanningTask, PendingRetry};
use super::planning_task_explicit_input;
use super::recommend::model_recommended_in_phase;
use super::task_id::PlanningTaskId;
use crate::app::{
    workspace_for_target, DeterministicRecommendationRefresh, PendingCredentialContinuation,
    PendingCredentialWork, PlanningDispatchView, PlanningTaskDispatch, ShellEffect, WorkflowPhase,
};
use crate::{ShellApp, ShellView};
use anyhow::Result;
use kuzushi_core::modules::PathSemantics;
use kuzushi_core::runtime::runtime_failure_metadata;
use kuzushi_core::{
    AgentRuntime, ExecutionAuthorization, Finding, NestedProjectKind, RuntimeFailureClass,
    ToolExecutionContext, TriageVerdict, WorkspaceTarget,
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
    pub(crate) fn resume_credential_continuation_effect(&mut self) -> Vec<ShellEffect> {
        let Some(pending) = self.engagement.take_pending_credential_continuation() else {
            return Vec::new();
        };
        if !self.credential_continuation_context_matches(&pending) {
            self.restore_unresumed_credential_work(pending);
            self.set_warn_notice(
                "planning",
                "Target or model changed while credentials were open · review the Scan selection before starting.",
            );
            return Vec::new();
        }
        if !self.configured_model_auth_ready() {
            self.reopen_unready_credential_continuation(pending);
            return Vec::new();
        }
        self.activate_credential_continuation(pending);
        vec![self.credential_continuation_dispatch_effect()]
    }

    fn credential_continuation_context_matches(
        &self,
        pending: &PendingCredentialContinuation,
    ) -> bool {
        self.target_owned().as_ref() == Some(&pending.target)
            && self.config().model.as_deref() == Some(pending.model.as_str())
    }

    fn reopen_unready_credential_continuation(&mut self, pending: PendingCredentialContinuation) {
        let provider = pending
            .model
            .split_once(':')
            .map(|(provider, _)| provider)
            .unwrap_or_default()
            .to_string();
        self.engagement.set_pending_credential_continuation(pending);
        self.open_credential_recovery(provider);
        self.set_warn_notice(
            "planning",
            "Credentials are still unavailable for the selected model; update them to continue.",
        );
    }

    fn activate_credential_continuation(&mut self, pending: PendingCredentialContinuation) {
        self.router.setup_mut().finish_editor();
        self.engagement.set_phase(pending.phase);
        match pending.work {
            PendingCredentialWork::CommittedPlan(plan) => self.engagement.queue_plan(plan),
            PendingCredentialWork::DeferredStep(step) => {
                self.engagement.push_expanded_step_front(step);
                self.engagement.resume_planning_queue();
            }
        }
        self.set_shell_view(ShellView::PlanningPicker);
        self.log(
            "planning",
            "credentials ready · resuming the selected Scan steps",
        );
    }

    fn credential_continuation_dispatch_effect(&self) -> ShellEffect {
        ShellEffect::DispatchNextPlanningTask(PlanningTaskDispatch {
            target: self.target_owned(),
            missing_workspace_message:
                "Scan paused: the active target became unavailable after authentication",
            success_view: Some(PlanningDispatchView::Activity),
        })
    }

    fn restore_unresumed_credential_work(&mut self, pending: PendingCredentialContinuation) {
        self.router.setup_mut().finish_editor();
        self.engagement.set_phase(pending.phase);
        if let PendingCredentialWork::DeferredStep(step) = pending.work {
            self.engagement.push_expanded_step_front(step);
            self.engagement.pause_planning_queue();
        }
        self.set_shell_view(ShellView::PlanningPicker);
    }

    pub(crate) fn dispatch_next_planning_task_effect(
        &mut self,
        dispatch: PlanningTaskDispatch,
    ) -> Vec<ShellEffect> {
        let workspace = match workspace_for_target(dispatch.target.as_ref()) {
            Ok(workspace) => workspace,
            Err(_) => {
                self.log("error", dispatch.missing_workspace_message);
                self.engagement.clear_planning_queue();
                return Vec::new();
            }
        };
        self.apply_planning_dispatch_view(dispatch.success_view);
        self.dispatch_next_planning_task(workspace)
    }

    fn apply_planning_dispatch_view(&mut self, view: Option<PlanningDispatchView>) {
        match view {
            // The background-run attachment captures the exact workflow
            // origin before it opens Run Focus. Switching here would reduce
            // every Setup/Planning launch origin to Activity.
            Some(PlanningDispatchView::Activity) => {}
            Some(PlanningDispatchView::Catalog) => self.set_shell_view(ShellView::Catalog),
            None => {}
        }
    }

    /// Dispatch the head of the planning queue (if any) on `workspace`.
    /// No-op when the queue is empty or any live job still owns an execution
    /// slot. Holding the step here keeps it queued instead of popping it and
    /// then losing it at the background-tool admission boundary.
    pub(crate) fn dispatch_next_planning_task(
        &mut self,
        workspace: WorkspaceTarget,
    ) -> Vec<ShellEffect> {
        if self.has_running_work() {
            self.log_planning_queue_stalled();
            return Vec::new();
        }
        let step = match self.next_planning_run_step(&workspace) {
            Ok(Some(step)) => step,
            Ok(None) => {
                self.engagement.clear_running_tool();
                return Vec::new();
            }
            Err(effects) => return effects,
        };
        self.dispatch_planning_run_step(step, workspace)
    }

    fn next_planning_run_step(
        &mut self,
        workspace: &WorkspaceTarget,
    ) -> Result<Option<PlanningRunStep>, Vec<ShellEffect>> {
        loop {
            if let Some(step) = self.engagement.pop_expanded_step() {
                return Ok(Some(step));
            }
            let Some(task) = self.engagement.pop_queued_task() else {
                return Ok(None);
            };
            match self.expand_planning_task(task, workspace) {
                Ok(steps) if steps.is_empty() => continue,
                Ok(steps) => self.engagement.replace_expanded_steps(steps),
                Err(error) => {
                    self.log(
                        "error",
                        format!("{} input invalid: {error:#}", task.tool_name()),
                    );
                    return Err(self.fail_planning_task_id(task, &format!("{error:#}")));
                }
            }
        }
    }

    fn dispatch_planning_run_step(
        &mut self,
        step: PlanningRunStep,
        workspace: WorkspaceTarget,
    ) -> Vec<ShellEffect> {
        if let Some((model, error)) = self.planning_step_credential_blocker(&step) {
            return self.pause_planning_step_for_credentials(
                step,
                workspace.root().to_path_buf(),
                model,
                error,
            );
        }
        self.engagement.set_running_planning_run_step(step.clone());
        if let Some(error) =
            self.langgraph_background_tool_launch_blocker(&step.tool_name, &step.input)
        {
            self.log("error", error.clone());
            return self.fail_planning_task(&step.tool_name, &error);
        }
        self.log(
            "planning",
            format!(
                "running planning step {} · {} queued after it",
                step.tool_name,
                self.pending_planning_step_count(),
            ),
        );
        let authorization =
            planning_step_authorization(step.task, self.step_configures_write_path(&step));
        self.start_authorized_background_tool(
            step.tool_name,
            step.input,
            workspace,
            "planning queue task in flight",
            self.session_thinking_level_owned(),
            authorization,
        );
        Vec::new()
    }

    fn planning_step_credential_blocker(&self, step: &PlanningRunStep) -> Option<(String, String)> {
        if !self
            .registry()
            .tool_wants_runtime(&step.tool_name, &step.input, self.config())
        {
            return None;
        }
        let model = kuzushi_core::modules::tool_execution_model(
            &step.tool_name,
            &step.input,
            self.config(),
        )?;
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let runtime = kuzushi_openai::LangGraphRuntime::from_config(self.config(), cwd).ok()?;
        let error = runtime.preflight_model_blocking(&model).err()?;
        let authentication = runtime_failure_metadata(&error)
            .is_some_and(|metadata| metadata.error_class == RuntimeFailureClass::Authentication);
        authentication.then(|| (model, error.to_string()))
    }

    fn pause_planning_step_for_credentials(
        &mut self,
        step: PlanningRunStep,
        target: PathBuf,
        model: String,
        error: String,
    ) -> Vec<ShellEffect> {
        let phase = self
            .engagement
            .current_phase()
            .unwrap_or(WorkflowPhase::Scan);
        let provider = model
            .split_once(':')
            .map(|(provider, _)| provider)
            .unwrap_or_default()
            .to_string();
        let tool_name = step.tool_name.clone();
        self.engagement.pause_planning_queue();
        self.engagement
            .set_pending_credential_continuation(PendingCredentialContinuation {
                target,
                phase,
                model,
                work: PendingCredentialWork::DeferredStep(step),
            });
        self.open_credential_recovery(provider);
        self.set_warn_notice(
            "planning",
            format!("{tool_name} is waiting for credentials · {error}"),
        );
        Vec::new()
    }

    pub(crate) fn pause_running_planning_step_for_credentials(
        &mut self,
        tool_name: &str,
        target: Option<PathBuf>,
        error: String,
    ) -> bool {
        if !self.engagement.running_tool_is(tool_name) {
            return false;
        }
        let Some(step) = self.engagement.take_running_planning_run_step() else {
            return false;
        };
        let Some(model) = kuzushi_core::modules::tool_execution_model(
            &step.tool_name,
            &step.input,
            self.config(),
        ) else {
            self.engagement.set_running_planning_run_step(step);
            return false;
        };
        let Some(target) = target.or_else(|| self.target_owned()) else {
            self.engagement.set_running_planning_run_step(step);
            return false;
        };
        self.pause_planning_step_for_credentials(step, target, model, error);
        true
    }

    /// True when the step's prepared input sets a write-capable path option
    /// (external-write or target-write semantics), which the executor refuses
    /// without an explicit authorization grant.
    fn step_configures_write_path(&self, step: &PlanningRunStep) -> bool {
        let Some(input) = step.input.as_object() else {
            return false;
        };
        let Some(tool) = self.registry().resolve_tool(&step.tool_name) else {
            return false;
        };
        tool.options.iter().any(|spec| {
            matches!(
                spec.path_semantics,
                Some(PathSemantics::ExternalWrite | PathSemantics::TargetWrite)
            ) && std::iter::once(spec.name.as_str())
                .chain(spec.aliases.iter().map(String::as_str))
                .any(|name| input.contains_key(name))
        })
    }

    fn expand_planning_task(
        &mut self,
        task: PlanningTaskId,
        workspace: &WorkspaceTarget,
    ) -> Result<Vec<PlanningRunStep>> {
        match task {
            PlanningTaskId::VerifyFindings => self.expand_finding_batch(
                task,
                eligible_verify_fingerprints(self.findings()),
                "no triaged findings ready for verification",
            ),
            PlanningTaskId::PatchFindings => self.expand_finding_batch(
                task,
                eligible_patch_fingerprints(self.findings()),
                "no confirmed true-positive findings ready for patching",
            ),
            PlanningTaskId::ReverseEngineerBinary => {
                self.expand_reverse_engineering_task(task, workspace)
            }
            _ => self.expand_single_planning_task(task),
        }
    }

    fn expand_finding_batch(
        &mut self,
        task: PlanningTaskId,
        fingerprints: Vec<String>,
        empty_reason: &str,
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
                self.step_with_extra_input(task, json!({ "fingerprint": fingerprint }))
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
        self.step_with_extra_input(task, json!({ "binary": binary.display().to_string() }))
            .map(|step| vec![step])
    }

    fn expand_single_planning_task(&self, task: PlanningTaskId) -> Result<Vec<PlanningRunStep>> {
        self.input_for_planning_task(task)
            .and_then(|input| self.validated_input_for_planning_task(task.tool_name(), input))
            .map(|input| {
                vec![PlanningRunStep {
                    task,
                    tool_name: task.tool_name().to_string(),
                    input,
                }]
            })
    }

    fn step_with_extra_input(&self, task: PlanningTaskId, extra: Value) -> Result<PlanningRunStep> {
        let input = self.input_for_planning_task_with_extra(task, extra)?;
        let input = self.validated_input_for_planning_task(task.tool_name(), input)?;
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
        let running = self
            .running_tool_name_owned()
            .unwrap_or_else(|| "active work".to_string());
        self.log(
            "planning",
            format!("plan queued ({queued} step(s)) — waiting for {running} to finish first",),
        );
    }

    /// Called after every completed background tool. If the completed
    /// tool belongs to our planning queue, advance to the next entry.
    pub(crate) fn advance_planning_queue_after_tool(
        &mut self,
        tool_name: &str,
    ) -> Vec<ShellEffect> {
        if !self.completed_current_planning_tool(tool_name) {
            return Vec::new();
        }
        self.engagement.clear_running_tool();
        self.reflect_planning_artifacts_after_tool();
        // Refresh the MCP attachment summary: the completed tool may
        // have produced an artifact whose absence was the only reason
        // an MCP wasn't attached.
        self.log_mcp_attachment_plan();
        if self.planning_queues_empty() {
            return self.finish_current_planning_phase();
        }
        vec![ShellEffect::DispatchNextPlanningTask(
            PlanningTaskDispatch {
                target: self.target_owned(),
                missing_workspace_message:
                    "planning queue paused: no active workspace; resume with /planning",
                success_view: None,
            },
        )]
    }

    /// The picker's checklist must reflect the artifact the completed tool
    /// just produced — re-entering the picker later may otherwise offer to
    /// re-run finished work from a stale snapshot.
    fn reflect_planning_artifacts_after_tool(&mut self) {
        self.engagement.planning_picker_mut().mark_artifacts_stale();
        if self.shell_view() != crate::app::ShellView::PlanningPicker {
            return;
        }
        if let Some(target) = self.target_owned() {
            self.engagement
                .planning_picker_mut()
                .refresh_artifact_states(&target);
        }
    }

    fn completed_current_planning_tool(&self, tool_name: &str) -> bool {
        !self.engagement.planning_paused()
            && self
                .engagement
                .running_tool()
                .is_some_and(|running| running == tool_name)
    }

    fn finish_current_planning_phase(&mut self) -> Vec<ShellEffect> {
        if self.current_phase_has_failures() {
            self.open_retry_gate();
            return Vec::new();
        }
        self.advance_to_next_phase()
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
        self.runtime_state.tool_run().is_ambient(name)
    }

    /// Completion hook for the recommender: map its tool picks to planning
    /// tasks, cache them for every phase, and refine the open picker.
    pub(crate) fn apply_model_recommendations(&mut self, result: &Value) -> Vec<ShellEffect> {
        let tasks = model_tasks_from_recommendation_result(result);
        if !tasks.is_empty() {
            let count = tasks.len();
            self.engagement.set_model_recommendations(tasks);
            // Refinement filters the rows the operator is looking at, so it is
            // keyed off the picker's own phase. The engagement may already have
            // advanced past it without those rows being rebuilt, and every
            // recommendation for the newer phase would then be filtered away.
            if matches!(self.shell_view(), ShellView::PlanningPicker) {
                if let Some(phase) = self.engagement.planning_picker().phase() {
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
        self.resume_pending_planning_after_recommendation()
    }

    fn resume_pending_planning_after_recommendation(&mut self) -> Vec<ShellEffect> {
        if self.planning_queues_empty()
            || self.engagement.has_running_tool()
            || self.tool_is_running()
        {
            return Vec::new();
        }
        vec![ShellEffect::DispatchNextPlanningTask(
            PlanningTaskDispatch {
                target: self.target_owned(),
                missing_workspace_message:
                    "planning queue paused: no active workspace; resume with /planning",
                success_view: None,
            },
        )]
    }

    fn refine_open_picker_with_model(&mut self, phase: WorkflowPhase) {
        let Some(model_tasks) = self.engagement.model_recommendations_cloned() else {
            return;
        };
        let phase_tasks: BTreeSet<PlanningTaskId> = self
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .map(|row| row.id)
            .collect();
        for task in model_recommended_in_phase(
            &model_tasks,
            self.engagement.planning_picker().tasks(),
            phase,
        ) {
            self.engagement
                .planning_picker_mut()
                .selected_mut()
                .insert(task);
            for dep in transitive_dependencies(task) {
                if phase_tasks.contains(&dep) {
                    self.engagement
                        .planning_picker_mut()
                        .selected_mut()
                        .insert(dep);
                }
            }
        }
    }

    /// A queued planning task failed. Record it (with any auto-retry hint),
    /// drop the queued tasks that transitively depended on it, and keep running
    /// the independent remainder — failure of one task no longer kills the run.
    pub(crate) fn fail_planning_task(&mut self, tool_name: &str, error: &str) -> Vec<ShellEffect> {
        self.record_planning_task_failure(tool_name, error);
        self.resume_or_advance_planning_queue()
    }

    fn fail_planning_task_id(&mut self, task: PlanningTaskId, error: &str) -> Vec<ShellEffect> {
        self.record_planning_task_failure_for(task, error);
        self.resume_or_advance_planning_queue()
    }

    pub(crate) fn pause_planning_task_after_failure(&mut self, tool_name: &str, error: &str) {
        self.record_planning_task_failure(tool_name, error);
        self.engagement.pause_planning_queue();
        self.log(
            "planning",
            format!("plan paused after {tool_name} failed; resume explicitly after review"),
        );
    }

    fn record_planning_task_failure(&mut self, tool_name: &str, error: &str) {
        let task = self
            .engagement
            .running_planning_task()
            .or_else(|| unambiguous_planning_task_for_tool(tool_name));
        self.engagement.clear_running_tool();
        let Some(task) = task else {
            return;
        };
        self.record_planning_task_failure_for(task, error);
    }

    fn record_planning_task_failure_for(&mut self, task: PlanningTaskId, error: &str) {
        let skipped = self.skip_queued_dependents(task);
        self.log_skipped_dependents(task, &skipped);
        self.engagement.record_failed_task(FailedPlanningTask {
            task,
            error: first_line(error),
            blocked: skipped,
        });
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

    fn resume_or_advance_planning_queue(&mut self) -> Vec<ShellEffect> {
        if self.engagement.planning_paused() {
            self.log(
                "planning",
                "planning queue remains paused; type `next` to review and resume",
            );
            return Vec::new();
        }
        if self.planning_queues_empty() {
            if self.current_phase_has_failures() {
                self.open_retry_gate();
                return Vec::new();
            }
            return self.advance_to_next_phase();
        }
        vec![ShellEffect::DispatchNextPlanningTask(
            PlanningTaskDispatch {
                target: self.target_owned(),
                missing_workspace_message: "planning queue paused: no active workspace",
                success_view: None,
            },
        )]
    }

    fn current_phase_has_failures(&self) -> bool {
        let Some(phase) = self.engagement.current_phase() else {
            return false;
        };
        self.engagement
            .failed_tasks()
            .iter()
            .any(|failed| failed.task.phase() == phase)
    }

    /// After a phase's queue drains (or the operator skips it), open the next
    /// phase's picker — 組 → 崩 → 作 → 掛 — or finish the engagement after 掛 KAKE.
    pub(crate) fn advance_to_next_phase(&mut self) -> Vec<ShellEffect> {
        let completed = self.engagement.current_phase();
        let effects = self.maybe_refresh_recommendations_after_map(completed);
        match completed.and_then(|phase| phase.next()) {
            Some(next) => self.open_or_announce_next_phase(next),
            None => self.finish_engagement(),
        }
        effects
    }

    fn maybe_refresh_recommendations_after_map(
        &mut self,
        completed: Option<WorkflowPhase>,
    ) -> Vec<ShellEffect> {
        if !self.should_refresh_recommendations_after_map(completed) {
            return Vec::new();
        }
        vec![ShellEffect::RefreshDeterministicRecommendations(
            DeterministicRecommendationRefresh {
                target: self.target_owned(),
            },
        )]
    }

    fn should_refresh_recommendations_after_map(&self, completed: Option<WorkflowPhase>) -> bool {
        completed == Some(WorkflowPhase::Map)
            && !self.engagement.phase_is_skipped(WorkflowPhase::Map)
            && !self.tool_is_running()
            && self.target().is_some()
    }

    pub(crate) fn refresh_deterministic_recommendations_effect(
        &mut self,
        refresh: DeterministicRecommendationRefresh,
    ) {
        let Ok(workspace) = workspace_for_target(refresh.target.as_ref()) else {
            return;
        };
        self.log("recommend", map_recommendation_notice(workspace.root()));
        if !crate::ui_view_models::recommendation_artifact_needs_refresh(self) {
            return;
        }
        self.start_deterministic_recommender(workspace);
    }

    fn start_deterministic_recommender(&mut self, workspace: WorkspaceTarget) {
        let input = json!({ "useModelRanking": false });
        let prepared = match self.prepare_background_tool_input(
            "module-recommender:recommend",
            input,
            &workspace,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.log("error", format!("recommendation input invalid: {error}"));
                return;
            }
        };
        let previous_auto_open = self.ui().auto_open_activity();
        self.ui_mut().set_auto_open_activity(false);
        self.start_authorized_prepared_background_tool(
            "module-recommender:recommend".to_string(),
            prepared,
            workspace,
            "deterministic module recommendations in flight",
            None,
            ExecutionAuthorization::default(),
        );
        self.ui_mut().set_auto_open_activity(previous_auto_open);
    }

    fn open_or_announce_next_phase(&mut self, next: WorkflowPhase) {
        if self.should_auto_open_next_phase() {
            self.open_phase_picker(next);
            return;
        }
        // `open_phase_picker` gates on `phases.stop_after`; announcing must
        // too, or advancing from a non-picker view walks past the configured
        // stopping boundary. The gate holds the phase and logs the reason.
        if self.phase_blocked_by_config(next) {
            return;
        }
        self.engagement.set_phase(next);
        self.set_success_notice(
            "phase",
            format!("{} ready — type `next` to continue", next.label()),
        );
    }

    fn should_auto_open_next_phase(&self) -> bool {
        if self.run_focus_is_background_owned() {
            return false;
        }
        match self.shell_view() {
            ShellView::PlanningPicker => true,
            ShellView::Activity => !self.foreground_run_focus_owns_activity(),
            _ => false,
        }
    }

    fn foreground_run_focus_owns_activity(&self) -> bool {
        self.shell_view() == ShellView::Activity
            && self.activity().is_some_and(|session| {
                !session.run_focus_backgrounded
                    && session
                        .run_focus_origin
                        .is_some_and(|origin| origin.auto_return)
            })
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
        self.advisory_mut().pending_retry = Some(PendingRetry { tasks });
        self.log(
            "phase",
            format!("{count} task(s) failed — retry? [y] retry · [n] skip"),
        );
    }

    /// Operator accepted the retry gate: re-queue every failed task plus the
    /// dependents that were skipped, then run them.
    pub(crate) fn retry_failed_tasks(&mut self) -> Vec<crate::app::ShellEffect> {
        let Some(pending) = self.advisory_mut().pending_retry.take() else {
            return Vec::new();
        };
        self.reset_retry_state();
        let tasks = self.retryable_tasks_from_failures(&pending.tasks);
        if tasks.is_empty() {
            self.log("phase", "no retryable failed tasks remain");
            self.finish_planning();
            return Vec::new();
        }
        let plan = topological_order(&tasks);
        self.log_retry_plan(&plan);
        self.queue_retry_plan(plan);
        self.reduce_dispatch_retry_plan()
    }

    fn reset_retry_state(&mut self) {
        self.engagement.clear_failures();
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
    }

    fn log_non_retryable_task(&mut self, item: &FailedPlanningTask) {
        self.log(
            "phase",
            format!("not retrying {} — {}", item.task.tool_name(), item.error),
        );
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

    fn reduce_dispatch_retry_plan(&mut self) -> Vec<crate::app::ShellEffect> {
        vec![crate::app::ShellEffect::DispatchNextPlanningTask(
            PlanningTaskDispatch {
                target: self.target_owned(),
                missing_workspace_message: "cannot retry without an active workspace",
                success_view: Some(PlanningDispatchView::Catalog),
            },
        )]
    }

    /// Operator declined the retry gate: drop the failures and move on.
    pub(crate) fn decline_retry(&mut self) {
        self.advisory_mut().pending_retry = None;
        self.engagement.clear_failures();
        self.engagement.clear_planning_queue();
        self.log("phase", "retry skipped");
        self.finish_planning();
    }

    /// Tool input for a planning task.
    fn input_for_planning_task(&self, task: PlanningTaskId) -> Result<Value> {
        self.input_for_planning_task_with_options(task)
    }

    fn input_for_planning_task_with_extra(
        &self,
        task: PlanningTaskId,
        extra: Value,
    ) -> Result<Value> {
        let mut input = planning_task_explicit_input(task, self.engagement.option_overrides());
        merge_input_object(&mut input, extra);
        Ok(input)
    }

    fn validated_input_for_planning_task(&self, tool_name: &str, input: Value) -> Result<Value> {
        self.registry()
            .prepare_tool_input(tool_name, input, Some(self.option_store()))
    }

    /// Planning is done. Return to the Workbench cockpit and leave the module
    /// recommender as an explicit operator action.
    fn finish_planning(&mut self) {
        self.engagement.clear_planning_queue();
        self.log("planning", "planning complete");
        if !self.foreground_run_focus_owns_activity() && !self.run_focus_is_background_owned() {
            self.open_workbench();
        }
        self.log(
            "recommend",
            "run `recommend` when you want suggested next modules",
        );
    }
}

/// A confirmed patch plan and any step whose input carries an
/// operator-configured write-capable path option run with scoped interactive
/// authorization: the operator typed the value into the picker and confirmed
/// the phase run, which is the consent the executor's write gate binds to.
fn planning_step_authorization(
    task: PlanningTaskId,
    configures_write_path: bool,
) -> ExecutionAuthorization {
    if task == PlanningTaskId::PatchFindings || configures_write_path {
        return ExecutionAuthorization::interactive_request();
    }
    ExecutionAuthorization::default()
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

fn unambiguous_planning_task_for_tool(tool_name: &str) -> Option<PlanningTaskId> {
    let mut matches = PlanningTaskId::ALL
        .iter()
        .copied()
        .filter(|task| task.tool_name() == tool_name);
    let task = matches.next()?;
    matches.next().is_none().then_some(task)
}

fn recommended_planning_task_for_tool(tool_name: &str) -> Option<PlanningTaskId> {
    PlanningTaskId::ALL
        .iter()
        .copied()
        .find(|task| task.tool_name() == tool_name)
}

fn failed_task_is_structurally_unsatisfiable(item: &FailedPlanningTask) -> bool {
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
        .filter_map(recommended_planning_task_for_tool)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{Severity, TriageOutcome, V2Config};
    use PlanningTaskId::*;

    #[test]
    fn shared_threat_model_tool_records_the_running_methodology() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.engagement
            .set_running_planning_step(BuildPastaThreatModel, "threat-model:build".to_string());

        app.pause_planning_task_after_failure("threat-model:build", "no topology");

        assert_eq!(app.engagement.failed_tasks()[0].task, BuildPastaThreatModel);
    }

    #[test]
    fn shared_threat_model_tool_keeps_distinct_activity_identity() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.engagement.queue_plan(vec![BuildPastaThreatModel]);
        app.engagement
            .set_running_planning_step(BuildStrideThreatModel, "threat-model:build".to_string());

        assert_eq!(
            app.engagement.planning_tool_sequence(),
            vec![
                "threat-model:build[stride]".to_string(),
                "threat-model:build[pasta]".to_string(),
            ]
        );
    }

    #[test]
    fn planning_activity_view_waits_until_run_attachment_captures_setup_origin() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Setup);

        app.apply_planning_dispatch_view(Some(PlanningDispatchView::Activity));

        assert_eq!(app.shell_view(), ShellView::Setup);
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
    fn model_refinement_follows_the_open_picker_phase_not_the_advanced_engagement() {
        // Run Focus finished Map and advanced the engagement to Scan without
        // rebuilding the checklist. Refinement must still resolve against the
        // Map rows on screen, or every recommendation is filtered away.
        let tmp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(tmp.path().to_path_buf()));
        app.engagement.planning_picker_mut().open_phase_profiled(
            WorkflowPhase::Map,
            vec![planning_row(BuildCodePropertyGraph)],
            BTreeSet::new(),
            false,
        );
        app.set_shell_view(ShellView::PlanningPicker);
        app.engagement.set_phase(WorkflowPhase::Scan);

        app.apply_model_recommendations(&json!({
            "data": { "recommendations": [{ "tool": "cpg:build" }] }
        }));

        assert!(app
            .engagement
            .planning_picker()
            .selected()
            .contains(&BuildCodePropertyGraph));
    }

    fn planning_row(id: PlanningTaskId) -> crate::app::PlanningTaskRow {
        crate::app::PlanningTaskRow {
            id,
            label: id.label(),
            tool_name: id.tool_name(),
            artifact_path: PathBuf::from("/dev/null"),
            artifact_state: crate::app::PlanningArtifactState::Missing,
            artifact_modified: None,
            model_backed: id.is_model_backed(),
            required_cli: None,
            cli_available: true,
            blocker: None,
            cached_detail: None,
            last_attempt: None,
        }
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
        *app.findings_mut() = vec![verify_me, skip_me];

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
        *app.findings_mut() = vec![patch_me, skip_me];

        let steps = app.expand_planning_task(PatchFindings, &workspace).unwrap();

        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tool_name, "patch:finding");
        assert_eq!(steps[0].input["fingerprint"], expected);
    }

    #[test]
    fn confirmed_patch_plan_requests_scoped_interactive_authorization() {
        assert_eq!(
            planning_step_authorization(PatchFindings, false),
            ExecutionAuthorization::interactive_request()
        );
        assert_eq!(
            planning_step_authorization(VerifyFindings, false),
            ExecutionAuthorization::default()
        );
    }

    #[test]
    fn operator_configured_write_path_option_requests_interactive_authorization() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let app = ShellApp::new(V2Config::default(), Some(&workspace));
        let step = |input: serde_json::Value| PlanningRunStep {
            task: PlanningTaskId::ScanFuzz,
            tool_name: "fuzz:run".to_string(),
            input,
        };

        assert!(app.step_configures_write_path(&step(json!({"workspaceRoot": "/tmp/ws"}))));
        assert!(!app.step_configures_write_path(&step(json!({"afeTarget": "appliance_regf"}))));
        assert_eq!(
            planning_step_authorization(PlanningTaskId::ScanFuzz, true),
            ExecutionAuthorization::interactive_request()
        );
        assert_eq!(
            planning_step_authorization(PlanningTaskId::ScanFuzz, false),
            ExecutionAuthorization::default()
        );
    }

    /// The journey dispatches both fuzz lanes with an empty preset input
    /// (the executor defaults to all built targets / auto mode), and the
    /// write-path escalation still guards workspaceRoot overrides.
    #[test]
    fn fuzz_lane_tasks_expand_to_single_deterministic_steps_with_empty_input() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        for (task, tool) in [
            (PlanningTaskId::ScanFuzzSweep, "fuzz:sweep"),
            (PlanningTaskId::ScanFuzzDifferential, "fuzz:differential"),
        ] {
            assert!(!task.is_model_backed(), "{task:?} must stay deterministic");
            let steps = app.expand_planning_task(task, &workspace).unwrap();
            assert_eq!(steps.len(), 1, "{task:?}");
            assert_eq!(steps[0].tool_name, tool, "{task:?}");
            // The journey adds no operator preset: the prepared input is the
            // descriptor defaults only — no target pin, no write-path override.
            let prepared = steps[0].input.as_object().expect("object input");
            for preset_key in ["afeTarget", "target", "workspaceRoot"] {
                assert!(!prepared.contains_key(preset_key), "{task:?} {preset_key}");
            }
            let write_path = PlanningRunStep {
                task,
                tool_name: tool.to_string(),
                input: json!({"workspaceRoot": "/tmp/ws"}),
            };
            assert!(app.step_configures_write_path(&write_path), "{task:?}");
            assert_eq!(
                planning_step_authorization(task, true),
                ExecutionAuthorization::interactive_request()
            );
            assert_eq!(
                planning_step_authorization(task, false),
                ExecutionAuthorization::default()
            );
        }
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
