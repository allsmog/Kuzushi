use crate::app::{
    ExecutionAuthorization, FailedPlanningTask, GuidedScanFlow, PendingPatch, PendingPrereqPrompt,
    PlanningOptionOverrides, PlanningPickerRouteState, PlanningRunStep, PlanningTaskId,
    PrereqChain, PrereqFinalInput, PrereqPlanAction, PrereqStep, RetryAdjustment, ThreatPatch,
    WorkflowPhase,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::rank::PlanProposal;

#[derive(Debug, Default)]
pub struct EngagementState {
    planning_run_queue: VecDeque<PlanningTaskId>,
    planning_expanded_queue: VecDeque<PlanningRunStep>,
    planning_running_tool: Option<String>,
    planning_running_task: Option<PlanningTaskId>,
    planning_paused: bool,
    planning_picker_route: PlanningPickerRouteState,
    pending_chain: Option<PrereqChain>,
    pending_prereq_prompt: Option<PendingPrereqPrompt>,
    pending_patch: Option<PendingPatch>,
    pending_threat_patch: Option<ThreatPatch>,
    planner_running: bool,
    plan_abort_requested: bool,
    threat_worker_running: bool,
    threat_abort_requested: bool,
    confirm_allowlist: BTreeSet<String>,
    confirm_denylist: BTreeSet<String>,
    pending_plan: Option<PlanProposal>,
    plan_cursor: usize,
    plan_skipped: BTreeSet<usize>,
    workflow_phase: Option<WorkflowPhase>,
    target_kind: Option<kuzushi_core::TargetKind>,
    planning_option_overrides: PlanningOptionOverrides,
    planning_failed: Vec<FailedPlanningTask>,
    planning_skipped_phases: BTreeSet<WorkflowPhase>,
    durable_skipped_phases: BTreeSet<WorkflowPhase>,
    planning_adjustments: BTreeMap<PlanningTaskId, RetryAdjustment>,
    model_recommended_tasks: Option<BTreeSet<PlanningTaskId>>,
    latest_phase_attempt: Option<kuzushi_core::workflow_attempts::PhaseAttemptRecord>,
    phase_attempt_ledger: kuzushi_core::workflow_attempts::PhaseAttemptLedger,
    phase_target_snapshot: Option<kuzushi_core::workflow_attempts::PhaseTargetSnapshot>,
    phase_attempt_projection_degraded: bool,
    pending_attempt_lineage: Option<(
        WorkflowPhase,
        String,
        kuzushi_core::workflow_attempts::PhaseAttemptDerivation,
    )>,
    guided_scan: Option<GuidedScanFlow>,
}

impl EngagementState {
    pub(crate) fn reset_for_target(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn current_phase(&self) -> Option<WorkflowPhase> {
        self.workflow_phase
    }

    pub(crate) fn set_phase(&mut self, phase: WorkflowPhase) {
        self.workflow_phase = Some(phase);
    }

    pub(crate) fn clear_phase(&mut self) {
        self.workflow_phase = None;
    }

    pub(crate) fn guided_scan(&self) -> Option<&GuidedScanFlow> {
        self.guided_scan.as_ref()
    }

    pub(crate) fn guided_scan_mut(&mut self) -> Option<&mut GuidedScanFlow> {
        self.guided_scan.as_mut()
    }

    pub(crate) fn set_guided_scan(&mut self, flow: GuidedScanFlow) {
        self.guided_scan = Some(flow);
    }

    pub(crate) fn clear_guided_scan(&mut self) {
        self.guided_scan = None;
    }

    pub(crate) fn set_phase_attempt_projection(
        &mut self,
        snapshot: Option<kuzushi_core::workflow_attempts::PhaseTargetSnapshot>,
        ledger: kuzushi_core::workflow_attempts::PhaseAttemptLedger,
    ) {
        self.set_phase_attempt_projection_health(snapshot, ledger, false);
    }

    pub(crate) fn set_phase_attempt_projection_health(
        &mut self,
        snapshot: Option<kuzushi_core::workflow_attempts::PhaseTargetSnapshot>,
        ledger: kuzushi_core::workflow_attempts::PhaseAttemptLedger,
        degraded: bool,
    ) {
        self.durable_skipped_phases = snapshot
            .as_ref()
            .map(|snapshot| ledger.skipped_phases_for(snapshot))
            .unwrap_or_default();
        self.latest_phase_attempt = snapshot
            .as_ref()
            .and_then(|snapshot| ledger.latest_for(snapshot))
            .cloned();
        self.phase_target_snapshot = snapshot;
        self.phase_attempt_ledger = ledger;
        self.phase_attempt_projection_degraded = degraded;
    }

    pub(crate) fn phase_attempt_projection_is_degraded(&self) -> bool {
        self.phase_attempt_projection_degraded
    }

    pub(crate) fn selected_phase_attempt(
        &self,
        phase: WorkflowPhase,
    ) -> Option<&kuzushi_core::workflow_attempts::PhaseAttemptRecord> {
        let snapshot = self.phase_target_snapshot.as_ref()?;
        self.phase_attempt_ledger.selected_for(phase, snapshot)
    }

    pub(crate) fn unresolved_phase_attempt(
        &self,
        phase: WorkflowPhase,
    ) -> Option<&kuzushi_core::workflow_attempts::PhaseAttemptRecord> {
        let snapshot = self.phase_target_snapshot.as_ref()?;
        self.phase_attempt_ledger.unresolved_for(phase, snapshot)
    }

    pub(crate) fn unresolved_phase_attempt_by_id(
        &self,
        phase: WorkflowPhase,
        attempt_id: &str,
    ) -> Option<&kuzushi_core::workflow_attempts::PhaseAttemptRecord> {
        let snapshot = self.phase_target_snapshot.as_ref()?;
        let record = self.phase_attempt_ledger.attempt(attempt_id)?;
        (record.completed.phase == phase
            && &record.completed.target_snapshot == snapshot
            && record.disposition.is_none())
        .then_some(record)
    }

    pub(crate) fn has_phase_attempt_for_target(&self, phase: WorkflowPhase) -> bool {
        self.phase_target_snapshot.as_ref().is_some_and(|snapshot| {
            self.phase_attempt_ledger
                .has_attempt_for_target(phase, snapshot)
        })
    }

    pub(crate) fn phase_target_snapshot(
        &self,
    ) -> Option<&kuzushi_core::workflow_attempts::PhaseTargetSnapshot> {
        self.phase_target_snapshot.as_ref()
    }

    pub(crate) fn proof_is_deferred_for(&self, finding: &kuzushi_core::Finding) -> bool {
        let Some(snapshot) = self.phase_target_snapshot.as_ref() else {
            return false;
        };
        let Some(scan_id) = finding
            .scan_id
            .as_deref()
            .filter(|scan_id| !scan_id.trim().is_empty())
        else {
            return false;
        };
        self.phase_attempt_ledger.proof_is_deferred_for(
            snapshot,
            &finding.fingerprint,
            finding.identity_id.as_deref(),
            scan_id,
        )
    }

    pub(crate) fn arm_attempt_lineage(
        &mut self,
        phase: WorkflowPhase,
        parent_attempt_id: String,
        derivation: kuzushi_core::workflow_attempts::PhaseAttemptDerivation,
    ) {
        self.pending_attempt_lineage = Some((phase, parent_attempt_id, derivation));
    }

    pub(crate) fn attempt_lineage(
        &self,
        phase: WorkflowPhase,
    ) -> Option<(
        String,
        kuzushi_core::workflow_attempts::PhaseAttemptDerivation,
    )> {
        self.pending_attempt_lineage
            .as_ref()
            .filter(|(pending_phase, _, _)| *pending_phase == phase)
            .map(|(_, parent, derivation)| (parent.clone(), *derivation))
    }

    pub(crate) fn clear_attempt_lineage(&mut self, phase: WorkflowPhase) {
        if self
            .pending_attempt_lineage
            .as_ref()
            .is_some_and(|(pending_phase, _, _)| *pending_phase == phase)
        {
            self.pending_attempt_lineage = None;
        }
    }

    pub(crate) fn mark_current_phase_skipped(&mut self) -> Option<WorkflowPhase> {
        let phase = self.workflow_phase?;
        self.planning_skipped_phases.insert(phase);
        Some(phase)
    }

    #[cfg(test)]
    pub(crate) fn skipped_phases(&self) -> &BTreeSet<WorkflowPhase> {
        &self.planning_skipped_phases
    }

    pub(crate) fn phase_is_skipped(&self, phase: WorkflowPhase) -> bool {
        self.planning_skipped_phases.contains(&phase)
            || self.durable_skipped_phases.contains(&phase)
    }

    pub(crate) fn projected_skipped_phases(&self) -> BTreeSet<WorkflowPhase> {
        self.planning_skipped_phases
            .union(&self.durable_skipped_phases)
            .copied()
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn target_kind(&self) -> Option<kuzushi_core::TargetKind> {
        self.target_kind
    }

    pub(crate) fn set_target_kind(&mut self, kind: kuzushi_core::TargetKind) {
        self.target_kind = Some(kind);
    }

    pub(crate) fn option_overrides(&self) -> &PlanningOptionOverrides {
        &self.planning_option_overrides
    }

    pub(crate) fn option_override_count(&self, task: PlanningTaskId) -> usize {
        self.planning_option_overrides
            .get(&task)
            .map(|values| values.len())
            .unwrap_or(0)
    }

    pub(crate) fn option_override_value(
        &self,
        task: PlanningTaskId,
        option_name: &str,
    ) -> Option<Value> {
        self.planning_option_overrides
            .get(&task)
            .and_then(|values| values.get(option_name))
            .cloned()
    }

    pub(crate) fn set_option_override(
        &mut self,
        task: PlanningTaskId,
        option_name: String,
        value: Value,
    ) {
        self.planning_option_overrides
            .entry(task)
            .or_default()
            .insert(option_name, value);
    }

    pub(crate) fn remove_option_override(&mut self, task: PlanningTaskId, option_name: &str) {
        let Some(values) = self.planning_option_overrides.get_mut(&task) else {
            return;
        };
        values.remove(option_name);
        if values.is_empty() {
            self.planning_option_overrides.remove(&task);
        }
    }

    pub(crate) fn option_overrides_with(
        &self,
        task: PlanningTaskId,
        option_name: String,
        value: Value,
    ) -> PlanningOptionOverrides {
        let mut overrides = self.planning_option_overrides.clone();
        overrides
            .entry(task)
            .or_default()
            .insert(option_name, value);
        overrides
    }

    pub(crate) fn pop_expanded_step(&mut self) -> Option<PlanningRunStep> {
        self.planning_expanded_queue.pop_front()
    }

    pub(crate) fn pop_queued_task(&mut self) -> Option<PlanningTaskId> {
        self.planning_run_queue.pop_front()
    }

    pub(crate) fn replace_expanded_steps(&mut self, steps: Vec<PlanningRunStep>) {
        self.planning_expanded_queue = VecDeque::from(steps);
    }

    pub(crate) fn queue_plan(&mut self, plan: Vec<PlanningTaskId>) {
        self.planning_run_queue = plan.into_iter().collect();
        self.planning_expanded_queue.clear();
        self.planning_paused = false;
    }

    pub(crate) fn clear_planning_queue(&mut self) {
        self.planning_run_queue.clear();
        self.planning_expanded_queue.clear();
        self.planning_paused = false;
    }

    pub(crate) fn pause_planning_queue(&mut self) {
        self.planning_paused = true;
        self.clear_running_tool();
    }

    pub(crate) fn planning_paused(&self) -> bool {
        self.planning_paused
    }

    pub(crate) fn pending_planning_step_count(&self) -> usize {
        self.planning_expanded_queue.len() + self.planning_run_queue.len()
    }

    pub(crate) fn planning_tool_sequence(&self) -> Vec<String> {
        self.planning_running_task
            .iter()
            .map(|task| task.activity_task_id())
            .chain(
                self.planning_expanded_queue
                    .iter()
                    .map(|step| step.task.activity_task_id()),
            )
            .chain(
                self.planning_run_queue
                    .iter()
                    .map(|task| task.activity_task_id()),
            )
            .collect()
    }

    pub(crate) fn planning_task_pending_after_current(&self, task: PlanningTaskId) -> bool {
        self.planning_expanded_queue
            .iter()
            .any(|step| step.task == task)
            || self.planning_run_queue.contains(&task)
    }

    pub(crate) fn planning_tool_pending_after_current(&self, tool_name: &str) -> bool {
        self.planning_expanded_queue
            .iter()
            .any(|step| step.tool_name == tool_name)
    }

    pub(crate) fn planning_queues_empty(&self) -> bool {
        self.planning_expanded_queue.is_empty() && self.planning_run_queue.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn queued_task_count(&self) -> usize {
        self.planning_run_queue.len()
    }

    #[cfg(test)]
    pub(crate) fn queued_task_contains(&self, task: PlanningTaskId) -> bool {
        self.planning_run_queue.contains(&task)
    }

    pub(crate) fn remove_queued_tasks_where(
        &mut self,
        mut should_remove: impl FnMut(PlanningTaskId) -> bool,
    ) -> Vec<PlanningTaskId> {
        let skipped: Vec<PlanningTaskId> = self
            .planning_run_queue
            .iter()
            .copied()
            .chain(self.planning_expanded_queue.iter().map(|step| step.task))
            .filter(|task| should_remove(*task))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        self.planning_run_queue
            .retain(|task| !skipped.contains(task));
        self.planning_expanded_queue
            .retain(|step| !skipped.contains(&step.task));
        skipped
    }

    pub(crate) fn running_tool(&self) -> Option<&str> {
        self.planning_running_tool.as_deref()
    }

    pub(crate) fn running_planning_task(&self) -> Option<PlanningTaskId> {
        self.planning_running_task
    }

    pub(crate) fn running_tool_is(&self, tool_name: &str) -> bool {
        self.running_tool() == Some(tool_name)
    }

    pub(crate) fn has_running_tool(&self) -> bool {
        self.planning_running_tool.is_some()
    }

    #[cfg(test)]
    pub(crate) fn set_running_tool(&mut self, tool_name: String) {
        self.planning_running_tool = Some(tool_name);
        self.planning_running_task = None;
    }

    pub(crate) fn set_running_planning_step(&mut self, task: PlanningTaskId, tool_name: String) {
        self.planning_running_tool = Some(tool_name);
        self.planning_running_task = Some(task);
    }

    pub(crate) fn clear_running_tool(&mut self) {
        self.planning_running_tool = None;
        self.planning_running_task = None;
    }

    pub(crate) fn planning_picker(&self) -> &PlanningPickerRouteState {
        &self.planning_picker_route
    }

    pub(crate) fn planning_picker_mut(&mut self) -> &mut PlanningPickerRouteState {
        &mut self.planning_picker_route
    }

    pub(crate) fn set_pending_chain(&mut self, chain: PrereqChain) {
        self.pending_chain = Some(chain);
    }

    pub(crate) fn has_pending_chain(&self) -> bool {
        self.pending_chain.is_some()
    }

    pub(crate) fn take_pending_chain(&mut self) -> Option<PrereqChain> {
        self.pending_chain.take()
    }

    pub(crate) fn clear_pending_chain(&mut self) {
        self.pending_chain = None;
    }

    pub(crate) fn has_pending_prereq_prompt(&self) -> bool {
        self.pending_prereq_prompt.is_some()
    }

    pub(crate) fn pending_prereq_prompt(&self) -> Option<&PendingPrereqPrompt> {
        self.pending_prereq_prompt.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn set_pending_prereq_prompt(&mut self, prompt: PendingPrereqPrompt) {
        self.pending_prereq_prompt = Some(prompt);
    }

    pub(crate) fn clear_pending_prereq_prompt(&mut self) {
        self.pending_prereq_prompt = None;
    }

    pub(crate) fn refresh_pending_prereq_prompt(&mut self) -> Option<PendingPrereqPrompt> {
        self.pending_prereq_prompt = self.pending_chain.as_ref().map(PrereqChain::plan);
        self.pending_prereq_prompt.clone()
    }

    pub(crate) fn clear_finished_final_tool(&mut self, tool_name: &str) -> bool {
        let finished = self
            .pending_chain
            .as_ref()
            .is_some_and(|chain| chain.final_dispatched && chain.final_tool == tool_name);
        if finished {
            self.pending_chain = None;
        }
        finished
    }

    pub(crate) fn drop_finished_prereq_step(&mut self, tool_name: &str) -> bool {
        let Some(chain) = self.pending_chain.as_mut() else {
            return false;
        };
        if chain.running_step.as_deref() != Some(tool_name) {
            return false;
        }
        let _ = chain.drop_first();
        chain.running_step = None;
        true
    }

    pub(crate) fn next_prereq_step(&self) -> Option<PrereqStep> {
        self.pending_chain.as_ref()?.next_step().cloned()
    }

    pub(crate) fn pending_chain_approved(&self) -> bool {
        self.pending_chain
            .as_ref()
            .is_some_and(|chain| chain.approved)
    }

    pub(crate) fn mark_prereq_plan_accepted(&mut self, action: PrereqPlanAction) -> Option<String> {
        let chain = self.pending_chain.as_mut()?;
        chain.approved = true;
        chain.regenerate_existing = action == PrereqPlanAction::Regenerate;
        Some(chain.final_tool.clone())
    }

    pub(crate) fn should_reuse_prereq_step(&self, step: &PrereqStep) -> bool {
        self.pending_chain
            .as_ref()
            .is_some_and(|chain| !chain.should_run_step(step))
    }

    pub(crate) fn drop_first_prereq_step(&mut self) {
        if let Some(chain) = self.pending_chain.as_mut() {
            let _ = chain.drop_first();
        }
    }

    pub(crate) fn mark_prereq_step_running(
        &mut self,
        tool_name: &str,
    ) -> Option<(String, Option<String>)> {
        let chain = self.pending_chain.as_mut()?;
        chain.running_step = Some(tool_name.to_string());
        Some((chain.final_tool.clone(), chain.final_thinking_level.clone()))
    }

    pub(crate) fn mark_final_chain_tool_dispatched(
        &mut self,
    ) -> Option<(
        String,
        PrereqFinalInput,
        Option<String>,
        ExecutionAuthorization,
    )> {
        let chain = self.pending_chain.as_mut()?;
        if chain.final_dispatched {
            return None;
        }
        chain.final_dispatched = true;
        Some((
            chain.final_tool.clone(),
            chain.final_input.clone(),
            chain.final_thinking_level.clone(),
            chain.authorization.clone(),
        ))
    }

    pub(crate) fn pending_patch(&self) -> Option<&PendingPatch> {
        self.pending_patch.as_ref()
    }

    pub(crate) fn set_pending_patch(&mut self, patch: PendingPatch) {
        self.pending_patch = Some(patch);
    }

    pub(crate) fn take_pending_patch(&mut self) -> Option<PendingPatch> {
        self.pending_patch.take()
    }

    pub(crate) fn clear_pending_patch(&mut self) {
        self.pending_patch = None;
    }

    pub(crate) fn pending_threat_patch(&self) -> Option<&ThreatPatch> {
        self.pending_threat_patch.as_ref()
    }

    pub(crate) fn set_pending_threat_patch(&mut self, patch: ThreatPatch) {
        self.pending_threat_patch = Some(patch);
    }

    pub(crate) fn take_pending_threat_patch(&mut self) -> Option<ThreatPatch> {
        self.pending_threat_patch.take()
    }

    pub(crate) fn clear_pending_threat_patch(&mut self) {
        self.pending_threat_patch = None;
    }

    pub(crate) fn has_pending_threat_patch(&self) -> bool {
        self.pending_threat_patch.is_some()
    }

    pub(crate) fn planner_running(&self) -> bool {
        self.planner_running
    }

    pub(crate) fn set_planner_running(&mut self, running: bool) {
        self.planner_running = running;
    }

    pub(crate) fn plan_abort_requested(&self) -> bool {
        self.plan_abort_requested
    }

    pub(crate) fn set_plan_abort_requested(&mut self, requested: bool) {
        self.plan_abort_requested = requested;
    }

    pub(crate) fn threat_worker_running(&self) -> bool {
        self.threat_worker_running
    }

    pub(crate) fn set_threat_worker_running(&mut self, running: bool) {
        self.threat_worker_running = running;
    }

    pub(crate) fn threat_abort_requested(&self) -> bool {
        self.threat_abort_requested
    }

    pub(crate) fn set_threat_abort_requested(&mut self, requested: bool) {
        self.threat_abort_requested = requested;
    }

    pub(crate) fn confirm_allowlist(&self) -> &BTreeSet<String> {
        &self.confirm_allowlist
    }

    pub(crate) fn confirm_denylist(&self) -> &BTreeSet<String> {
        &self.confirm_denylist
    }

    pub(crate) fn remember_confirm_decision(&mut self, key: String, outcome: bool) {
        if outcome {
            self.confirm_denylist.remove(&key);
            self.confirm_allowlist.insert(key);
        } else {
            self.confirm_allowlist.remove(&key);
            self.confirm_denylist.insert(key);
        }
    }

    pub(crate) fn set_model_recommendations(&mut self, tasks: BTreeSet<PlanningTaskId>) {
        self.model_recommended_tasks = Some(tasks);
    }

    pub(crate) fn model_recommendations(&self) -> Option<&BTreeSet<PlanningTaskId>> {
        self.model_recommended_tasks.as_ref()
    }

    pub(crate) fn model_recommendations_cloned(&self) -> Option<BTreeSet<PlanningTaskId>> {
        self.model_recommended_tasks.clone()
    }

    pub(crate) fn failed_tasks(&self) -> &[FailedPlanningTask] {
        &self.planning_failed
    }

    pub(crate) fn failed_tasks_cloned(&self) -> Vec<FailedPlanningTask> {
        self.planning_failed.clone()
    }

    pub(crate) fn failed_task_ids(&self) -> BTreeSet<PlanningTaskId> {
        self.planning_failed.iter().map(|item| item.task).collect()
    }

    pub(crate) fn has_failed_tasks(&self) -> bool {
        !self.planning_failed.is_empty()
    }

    pub(crate) fn record_failed_task(&mut self, failed: FailedPlanningTask) {
        self.planning_failed.push(failed);
    }

    pub(crate) fn clear_failures_and_adjustments(&mut self) {
        self.planning_failed.clear();
        self.planning_adjustments.clear();
    }

    pub(crate) fn insert_retry_adjustment(
        &mut self,
        task: PlanningTaskId,
        adjustment: RetryAdjustment,
    ) {
        self.planning_adjustments.insert(task, adjustment);
    }

    pub(crate) fn retry_adjustment(&self, task: PlanningTaskId) -> Option<&RetryAdjustment> {
        self.planning_adjustments.get(&task)
    }

    pub(crate) fn pending_plan(&self) -> Option<&PlanProposal> {
        self.pending_plan.as_ref()
    }

    pub(crate) fn has_pending_plan(&self) -> bool {
        self.pending_plan.is_some()
    }

    pub(crate) fn set_pending_plan(&mut self, plan: PlanProposal) {
        self.reset_plan_review_state();
        self.pending_plan = Some(plan);
    }

    pub(crate) fn take_pending_plan(&mut self) -> Option<PlanProposal> {
        self.pending_plan.take()
    }

    pub(crate) fn discard_pending_plan(&mut self) -> bool {
        let had_plan = self.pending_plan.take().is_some();
        if had_plan {
            self.reset_plan_review_state();
        }
        had_plan
    }

    pub(crate) fn reset_plan_review_state(&mut self) {
        self.plan_cursor = 0;
        self.plan_skipped.clear();
    }

    pub(crate) fn plan_change_count(&self) -> usize {
        self.pending_plan
            .as_ref()
            .map(|plan| plan.changes.len())
            .unwrap_or(0)
    }

    pub(crate) fn plan_cursor_clamped(&self) -> usize {
        let total = self.plan_change_count();
        if total == 0 {
            return 0;
        }
        self.plan_cursor.min(total - 1)
    }

    pub(crate) fn plan_change_skipped(&self, idx: usize) -> bool {
        self.plan_skipped.contains(&idx)
    }

    pub(crate) fn move_plan_cursor(&mut self, delta: i32) {
        let total = self.plan_change_count();
        if total == 0 {
            self.plan_cursor = 0;
            return;
        }
        let cursor = self.plan_cursor.min(total - 1) as i32;
        self.plan_cursor = (cursor + delta).clamp(0, total as i32 - 1) as usize;
    }

    pub(crate) fn move_plan_cursor_to_start(&mut self) {
        self.plan_cursor = 0;
    }

    pub(crate) fn move_plan_cursor_to_end(&mut self) {
        let total = self.plan_change_count();
        if total > 0 {
            self.plan_cursor = total - 1;
        }
    }

    pub(crate) fn toggle_plan_change_skip(&mut self) {
        if self.plan_change_count() == 0 {
            return;
        }
        let idx = self.plan_cursor_clamped();
        if !self.plan_skipped.remove(&idx) {
            self.plan_skipped.insert(idx);
        }
    }
}
