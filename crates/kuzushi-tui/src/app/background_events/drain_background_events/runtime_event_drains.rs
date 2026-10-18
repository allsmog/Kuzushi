use super::*;
use std::time::{Duration, Instant};

#[cfg(test)]
mod context_map_result_tests;
#[cfg(test)]
mod input_return_tests;
mod phase_result_destination;
#[cfg(test)]
mod planner_result_tests;
mod receipt_notice;
use receipt_notice::run_receipt_notice;
#[cfg(test)]
mod setup_map_result_tests;
#[cfg(test)]
mod trace_phase_result_tests;
#[cfg(test)]
mod trace_return_tests;

const EVENT_DRAIN_LIMIT: usize = 256;
pub(super) const TRACE_DRAIN_LIMIT: usize = 512;
pub(super) const JOB_DRAIN_LIMIT: usize = EVENT_DRAIN_LIMIT + TRACE_DRAIN_LIMIT;
const JOB_DRAIN_TIME_SLICE: Duration = Duration::from_millis(3);

struct RunFocusCompletion {
    origin: Option<RunFocusOrigin>,
    backgrounded: bool,
    receipt: Option<RunFocusReceipt>,
    answer_acknowledgement: Option<String>,
    pending_viz: Option<crate::scene3d::VizPage>,
}

impl RunFocusCompletion {
    fn should_restore(&self, current_view: ShellView) -> bool {
        self.origin.is_some_and(|origin| origin.auto_return)
            && !self.backgrounded
            && current_view == ShellView::Activity
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct JobDrainOutcome {
    pub(crate) changed: bool,
    pub(crate) time_slice_exhausted: bool,
}

impl ShellApp {
    pub fn drain_background_events(&mut self) -> bool {
        self.run_background_maintenance() | self.drain_job_events()
    }

    pub(crate) fn run_background_maintenance(&mut self) -> bool {
        self.reap_worker_handles()
            | self.cancel_timed_out_workers()
            | self.apply_review_decision_write_result()
            | self.apply_report_export_result()
            | self.apply_view_hydration_results()
            | self.apply_answer_recovery()
            | self.drain_context_checkpoints()
            | self.drain_study_checkpoints()
            | self.apply_project_scope_discovery_results()
            | self.apply_target_candidate_discovery_results()
            | self.drain_idle_steer_queue()
            | self.finalize_run_focus_if_idle()
    }

    pub(crate) fn drain_job_events(&mut self) -> bool {
        self.drain_job_events_with_outcome().changed
    }

    pub(crate) fn drain_job_events_with_outcome(&mut self) -> JobDrainOutcome {
        self.drain_job_events_for(JOB_DRAIN_TIME_SLICE)
    }

    pub(crate) fn drain_job_events_for(&mut self, time_slice: Duration) -> JobDrainOutcome {
        let started_at = Instant::now();
        let mut outcome = JobDrainOutcome::default();
        for inspected in 0..JOB_DRAIN_LIMIT {
            if inspected > 0 && started_at.elapsed() >= time_slice {
                outcome.time_slice_exhausted = true;
                break;
            }
            match self.jobs_mut().drain_one() {
                JobDrainResult::Event(event) => {
                    outcome.changed |= update_and_execute_effects(self, Msg::Job(event));
                }
                JobDrainResult::Stale => {}
                JobDrainResult::Empty => break,
            }
            outcome.time_slice_exhausted = inspected + 1 == JOB_DRAIN_LIMIT;
        }
        outcome
    }

    pub(crate) fn apply_job_event(&mut self, event: ShellEvent) -> Vec<ShellEffect> {
        let kind = event.kind();
        let finishes_slot = self.job_event_finishes_slot(&event);
        let owns_run_focus = self.job_owns_run_focus(kind);
        let terminal_fallback = finishes_slot.then(|| run_focus_event_outcome(&event));
        let mut effects = self.apply_current_job_event(event);
        if finishes_slot {
            if owns_run_focus {
                self.mark_run_focus_terminal_pending(
                    terminal_fallback.as_deref().unwrap_or("completed"),
                );
            }
            self.clear_finished_job(kind);
            let after_persistence = matches!(
                effects.first(),
                Some(
                    ShellEffect::RecordAgentRun(_)
                        | ShellEffect::RecordScanRun(_)
                        | ShellEffect::RecordToolRun(_)
                )
            ) as usize;
            effects.insert(after_persistence, ShellEffect::FinalizeJob(kind));
        }
        effects
    }

    pub(crate) fn finalize_job_effect(&mut self, kind: JobKind) {
        if self.is_auxiliary_agent_job(kind) {
            self.jobs_mut().finish(kind);
            self.runtime_state.clear_cleared_agent_run();
            return;
        }
        self.drain_terminal_lifecycle_events();
        self.catch_up_focused_run_from_disk();
        self.jobs_mut().finish(kind);
        if kind == JobKind::Agent {
            self.runtime_state.clear_cleared_agent_run();
        }
        let effects = self.advance_steer_queue();
        EffectRuntime::execute(self, effects);
    }

    fn job_owns_run_focus(&self, kind: JobKind) -> bool {
        !self.is_auxiliary_agent_job(kind)
    }

    fn is_auxiliary_agent_job(&self, kind: JobKind) -> bool {
        kind == JobKind::Agent
            && (self
                .agent_chat()
                .is_some_and(|agent| agent.auxiliary_read_only)
                || self
                    .runtime_state
                    .cleared_agent_run()
                    .is_some_and(|run| run.auxiliary_read_only))
    }

    fn drain_terminal_lifecycle_events(&mut self) {
        for _ in 0..JOB_DRAIN_LIMIT {
            let event = match self.jobs_mut().drain_one() {
                JobDrainResult::Event(event) => event,
                JobDrainResult::Stale => continue,
                JobDrainResult::Empty => break,
            };
            let effects = self.apply_current_job_event(event);
            EffectRuntime::execute(self, effects);
        }
    }

    fn catch_up_focused_run_from_disk(&mut self) {
        if let Err(error) = self.try_catch_up_focused_run_from_disk() {
            self.log(
                "run",
                format!("terminal lifecycle catch-up failed: {error}"),
            );
        }
    }

    fn try_catch_up_focused_run_from_disk(&mut self) -> anyhow::Result<()> {
        let Some((target, run_id, applied_seq)) = self.focused_run_catch_up_request() else {
            return Ok(());
        };
        let Some(read) = kuzushi_core::run_lifecycle::read_run_items(&target, &run_id)? else {
            return Ok(());
        };
        let session = self.activity_mut().expect("activity checked above");
        for item in read.items.into_iter().filter(|item| item.seq > applied_seq) {
            session.apply_run_item(item)?;
        }
        Ok(())
    }

    fn focused_run_catch_up_request(&self) -> Option<(PathBuf, String, u64)> {
        let target = self.target_owned()?;
        let session = self.activity()?;
        Some((
            target,
            session.run_id.clone(),
            session.run_projection.last_committed_seq,
        ))
    }

    fn mark_run_focus_terminal_pending(&mut self, fallback: &str) {
        let canceled = self.activity().is_some_and(|session| {
            session
                .tasks
                .values()
                .any(|task| task.state == DagTaskState::Canceled)
        });
        let outcome = if canceled {
            "canceled".to_string()
        } else {
            self.live_activity()
                .filter(|activity| !activity.phase.active())
                .map(|activity| activity.phase.label().to_string())
                .unwrap_or_else(|| fallback.to_string())
        };
        if let Some(run_id) = self.activity().map(|session| session.run_id.clone()) {
            let tool_name = self
                .running_tool_name_owned()
                .or_else(|| {
                    self.live_activity()
                        .map(|activity| activity.subject.clone())
                })
                .unwrap_or_else(|| "shell".to_string());
            self.record_session_event(
                kuzushi_core::session_transcript::SessionEvent::RunFinished {
                    run_id,
                    tool_name,
                    status: outcome.clone(),
                },
            );
        }
        if let Some(session) = self.activity_mut() {
            session.mark_run_focus_terminal_pending(outcome);
        }
    }

    fn finalize_run_focus_if_idle(&mut self) -> bool {
        if !self.run_focus_sequence_is_settled() {
            return false;
        }
        let Some(completion) = self.pending_run_focus_completion() else {
            return false;
        };
        self.clear_pending_run_focus_completion();
        let restored = self.restore_run_focus_origin(&completion);
        self.publish_run_focus_receipt(
            completion.receipt,
            completion.answer_acknowledgement.as_deref(),
        );
        // Deferred decks open only after the receipt refresh above: it
        // invalidates the view caches the deck renders from, so opening
        // earlier lands on an empty frame until manually reopened.
        if restored {
            self.open_completed_run_destination(completion.origin, completion.pending_viz);
        }
        true
    }

    fn pending_run_focus_completion(&self) -> Option<RunFocusCompletion> {
        let session = self.activity()?;
        session.run_focus_terminal_pending.then(|| {
            let mut receipt = session.run_focus_receipt.clone();
            if let Some(receipt) = receipt.as_mut() {
                receipt.cost = session.run_focus_cost_label();
            }
            RunFocusCompletion {
                origin: session.run_focus_origin,
                backgrounded: session.run_focus_backgrounded,
                receipt,
                answer_acknowledgement: session.operator_answer_acknowledgement.clone(),
                pending_viz: session.run_focus_pending_viz,
            }
        })
    }

    fn clear_pending_run_focus_completion(&mut self) {
        if let Some(session) = self.activity_mut() {
            session.run_focus_terminal_pending = false;
            session.run_focus_pending_viz = None;
        }
    }

    fn restore_run_focus_origin(&mut self, completion: &RunFocusCompletion) -> bool {
        if !completion.should_restore(self.shell_view()) {
            return false;
        }
        let origin = completion.origin.expect("restore decision requires origin");
        self.set_shell_view(origin.view);
        self.set_input_mode(self.completed_reader_input_mode(origin.input_mode));
        true
    }

    fn completed_reader_input_mode(&self, origin: InputMode) -> InputMode {
        if !self.input().is_empty() {
            return InputMode::Prompt;
        }
        if self.prove_detail_owns_controls() {
            InputMode::Navigate
        } else {
            origin
        }
    }

    fn enrich_run_focus_receipt(&mut self, receipt: &mut RunFocusReceipt) {
        let Some(target) = self.target_owned() else {
            return;
        };
        let nested = nested_run_refs(&target, &receipt.run_refs);
        extend_unique_run_refs(&mut receipt.run_refs, nested);
        let (findings, artifacts) = receipt_run_changes(&target, &receipt.run_refs);
        receipt.changed_findings = findings;
        receipt.changed_artifacts = artifacts.into_iter().collect();
        let (summaries, hydration, issues) =
            receipt_run_result_summaries(&target, &receipt.run_refs);
        receipt.result_summaries = summaries;
        if let Some(session) = self.activity_mut() {
            session.run_presentation_hydration.merge(hydration);
        }
        for issue in issues {
            self.log("run", issue);
        }
    }

    fn reconcile_durable_phase_outcome(&self, receipt: &mut RunFocusReceipt) -> Option<String> {
        let target = self.target()?;
        let phase = receipt.origin_phase?;
        let run_refs = self.canonical_descriptor_run_refs(target, phase, &receipt.run_refs);
        if run_refs.is_empty() {
            return None;
        }
        let outcome = durable_phase_attempt_outcome(target, phase, &run_refs, &receipt.outcome);
        let outcome =
            live_health_adjusted_outcome(Some(target), outcome, &run_refs, self.activity());
        receipt.outcome = phase_attempt_outcome_label(outcome).to_string();
        map_evidence_blocker(target, phase, &run_refs, outcome)
    }

    /// Keep the single `n` action truthful for the result that just landed.
    /// The operator still selects the attempt before reality is re-derived;
    /// this only decides whether the card names the next phase or Report.
    fn tailor_phase_result_destination(&self, receipt: &mut RunFocusReceipt) {
        receipt.origin_phase = self.receipt_phase_result_owner(receipt);
        let Some(phase) = receipt.origin_phase else {
            receipt.attempt_id = None;
            let policy = phase_result_policy(
                None,
                phase_attempt_outcome_from_label(&receipt.outcome),
                false,
            );
            receipt.actions = policy.actions;
            receipt.recommended_next = policy.recommended_next;
            return;
        };
        let report = phase_result_routes_to_report(self, receipt, phase);
        let policy = self.terminal_phase_result_policy(
            phase,
            phase_attempt_outcome_from_label(&receipt.outcome),
            report,
            &receipt.run_refs,
        );
        receipt.actions = policy.actions;
        receipt.recommended_next = policy.recommended_next;
    }

    fn receipt_phase_result_owner(&self, receipt: &RunFocusReceipt) -> Option<WorkflowPhase> {
        let phase = receipt.origin_phase?;
        let Some(target) = self.target() else {
            return Some(phase);
        };
        (!self
            .canonical_descriptor_run_refs(target, phase, &receipt.run_refs)
            .is_empty())
        .then_some(phase)
    }

    fn persist_phase_attempt(&mut self, receipt: &mut RunFocusReceipt) {
        use kuzushi_core::workflow_attempts::append_phase_attempt_completed_with_v2_receipt;

        let Some((target, completed)) = self.effectful_phase_attempt(receipt) else {
            return;
        };
        let phase = completed.phase;
        let attempt_id = completed.attempt_id.clone();
        match append_phase_attempt_completed_with_v2_receipt(&target, completed) {
            Ok(appended) => {
                self.apply_live_phase_receipt(&target, &appended.receipt);
                receipt.attempt_id = Some(attempt_id.clone());
                self.engagement.clear_attempt_lineage(phase);
                self.refresh_phase_attempt_projection();
                self.bind_guided_phase_result(phase, attempt_id);
            }
            Err(error) => self.log(
                "workflow",
                format!(
                    "run completed, but its phase attempt receipt could not be recorded: {error}"
                ),
            ),
        }
    }

    fn apply_live_phase_receipt(
        &mut self,
        target: &std::path::Path,
        envelope: &kuzushi_core::run_lifecycle::RunItemEnvelopeV1,
    ) {
        if let Err(error) = self.catch_up_live_phase_receipt(target, envelope) {
            self.log(
                "workflow",
                format!("typed phase receipt is durable but live delivery failed: {error}"),
            );
        }
    }

    fn catch_up_live_phase_receipt(
        &mut self,
        target: &std::path::Path,
        receipt: &kuzushi_core::run_lifecycle::RunItemEnvelopeV1,
    ) -> anyhow::Result<()> {
        use kuzushi_core::run_lifecycle::CommittedRange;
        let Some(applied_seq) = self.activity().and_then(|session| {
            (session.run_id == receipt.run_id.as_str())
                .then_some(session.run_projection.last_committed_seq)
        }) else {
            return Ok(());
        };
        if applied_seq >= receipt.seq {
            return Ok(());
        }
        let items = durable_phase_receipt_prefix(target, receipt, applied_seq)?;
        let session = self.activity_mut().expect("activity checked above");
        session.observe_committed_range(CommittedRange {
            first_seq: applied_seq.saturating_add(1),
            through_seq: receipt.seq,
        });
        for item in items {
            session.apply_run_item(item)?;
        }
        Ok(())
    }

    fn effectful_phase_attempt(
        &self,
        receipt: &RunFocusReceipt,
    ) -> Option<(
        std::path::PathBuf,
        kuzushi_core::workflow_attempts::PhaseAttemptCompleted,
    )> {
        use kuzushi_core::workflow_attempts::{PhaseAttemptCompleted, PhaseTargetSnapshot};

        let target = self.target_owned()?;
        let phase = receipt.origin_phase?;
        let run_refs = self.canonical_descriptor_run_refs(&target, phase, &receipt.run_refs);
        if run_refs.is_empty() {
            return None;
        }
        let completed = PhaseAttemptCompleted::new(
            phase,
            run_refs.clone(),
            PhaseTargetSnapshot::capture(&target),
            durable_phase_attempt_outcome(&target, phase, &run_refs, &receipt.outcome),
        )
        .with_receipt(receipt.durable_metadata());
        let completed = completed_with_attempt_id(completed, receipt.attempt_id.as_deref());
        let completed = completed_with_map_blocker(completed, &target, phase, &run_refs);
        let completed = completed_with_live_health_gate(completed, Some(&target), self.activity());
        let completed = completed_with_lineage(completed, self.engagement.attempt_lineage(phase));
        Some((target, completed))
    }

    fn canonical_descriptor_run_refs(
        &self,
        target: &std::path::Path,
        phase: WorkflowPhase,
        run_refs: &[String],
    ) -> Vec<String> {
        run_refs
            .iter()
            .filter_map(|run_id| self.canonical_descriptor_run_ref(target, phase, run_id))
            .collect()
    }

    fn canonical_descriptor_run_ref(
        &self,
        target: &std::path::Path,
        phase: WorkflowPhase,
        run_id: &str,
    ) -> Option<String> {
        let summary = kuzushi_core::load_run_summary(target, run_id).ok()?;
        let tool = terminal_descriptor_run_tool(&summary)?;
        let descriptor = self.registry().resolve_tool(tool)?;
        (kuzushi_core::modules::phase_result_phase(descriptor) == Some(phase))
            .then_some(summary.run_id)
    }

    fn run_focus_sequence_is_settled(&self) -> bool {
        !self.has_running_work()
            && !self.run_focus_continuation_pending()
            && self.steer_queue().len() == 0
    }

    fn run_focus_continuation_pending(&self) -> bool {
        self.engagement.has_pending_chain()
            || self.engagement.has_pending_prereq_prompt()
            || (!self.engagement.planning_paused() && !self.engagement.planning_queues_empty())
    }

    fn apply_current_job_event(&mut self, event: ShellEvent) -> Vec<ShellEffect> {
        match event {
            ShellEvent::RunItem(item) => self.apply_committed_run_item(item),
            ShellEvent::RunItemsDurable { run_id, range } => {
                self.apply_run_item_high_watermark(run_id, range)
            }
            ShellEvent::RunItemsDerivativesApplied { run_id, range } => {
                self.apply_run_item_derivative_watermark(run_id, range)
            }
            ShellEvent::RunItemsFault { run_id, fault } => {
                self.apply_run_item_writer_fault(run_id, fault)
            }
            ShellEvent::RunItemsDeliveryFault { run_id, fault } => {
                self.apply_run_item_delivery_fault(run_id, fault)
            }
            ShellEvent::Scan(event) => self.apply_scan_event(event),
            ShellEvent::Tool(event) => self.apply_tool_event(event),
            ShellEvent::Agent(event) => self.apply_agent_event(event),
            ShellEvent::OperatorQuestion(envelope) => {
                self.apply_operator_question(envelope);
                Vec::new()
            }
            ShellEvent::OperatorQuestionCompleted(completed) => {
                self.apply_operator_question_completed(completed);
                Vec::new()
            }
            ShellEvent::CredentialQuestionRouted { request_id, run_id } => {
                self.apply_credential_question_route(&request_id, &run_id)
            }
            ShellEvent::Plan(event) => {
                self.apply_plan_event(event);
                Vec::new()
            }
            ShellEvent::Threat(event) => {
                self.apply_threat_patch_event(event);
                Vec::new()
            }
        }
    }

    fn apply_committed_run_item(
        &mut self,
        item: kuzushi_core::run_lifecycle::RunItemEnvelopeV1,
    ) -> Vec<ShellEffect> {
        let run_id = item.run_id.as_str().to_string();
        if self
            .activity()
            .is_some_and(|session| session.run_id != run_id)
        {
            self.log(
                "run",
                format!("ignored stale lifecycle item for run {run_id}"),
            );
            return Vec::new();
        }
        let cancel_requested =
            self.scan().is_some_and(|scan| scan.abort_requested) || self.tool_abort_requested();
        let session = self.activity_or_insert_with(|| ActivitySession::new(run_id));
        if let Err(error) = session.apply_run_item(item) {
            self.log("run", format!("typed run projection degraded: {error}"));
        } else if cancel_requested {
            session.mark_active_tasks_canceling();
        }
        Vec::new()
    }

    fn apply_run_item_high_watermark(
        &mut self,
        run_id: String,
        range: kuzushi_core::run_lifecycle::CommittedRange,
    ) -> Vec<ShellEffect> {
        if self
            .activity()
            .is_some_and(|session| session.run_id != run_id)
        {
            self.log(
                "run",
                format!("ignored stale durability update for run {run_id}"),
            );
            return Vec::new();
        }
        self.activity_or_insert_with(|| ActivitySession::new(run_id))
            .observe_committed_range(range);
        Vec::new()
    }

    fn apply_run_item_writer_fault(
        &mut self,
        run_id: String,
        fault: kuzushi_core::run_lifecycle::RunItemWriterFault,
    ) -> Vec<ShellEffect> {
        if self
            .activity()
            .is_some_and(|session| session.run_id != run_id)
        {
            self.log(
                "run",
                format!("ignored stale persistence fault for run {run_id}"),
            );
            return Vec::new();
        }
        self.activity_or_insert_with(|| ActivitySession::new(run_id))
            .record_run_item_writer_fault(fault);
        Vec::new()
    }

    fn apply_run_item_delivery_fault(
        &mut self,
        run_id: String,
        fault: kuzushi_core::run_lifecycle::RunItemDeliveryFault,
    ) -> Vec<ShellEffect> {
        if self
            .activity()
            .is_some_and(|session| session.run_id != run_id)
        {
            self.log(
                "run",
                format!("ignored stale delivery fault for run {run_id}"),
            );
            return Vec::new();
        }
        self.activity_or_insert_with(|| ActivitySession::new(run_id))
            .record_run_item_delivery_fault(fault);
        Vec::new()
    }

    fn apply_run_item_derivative_watermark(
        &mut self,
        run_id: String,
        range: kuzushi_core::run_lifecycle::CommittedRange,
    ) -> Vec<ShellEffect> {
        if self
            .activity()
            .is_some_and(|session| session.run_id != run_id)
        {
            self.log(
                "run",
                format!("ignored stale derivative range for run {run_id}"),
            );
            return Vec::new();
        }
        self.activity_or_insert_with(|| ActivitySession::new(run_id))
            .observe_derivative_range(range);
        Vec::new()
    }

    fn job_event_finishes_slot(&self, event: &ShellEvent) -> bool {
        match event {
            ShellEvent::RunItem(_)
            | ShellEvent::RunItemsDurable { .. }
            | ShellEvent::RunItemsDerivativesApplied { .. }
            | ShellEvent::RunItemsFault { .. }
            | ShellEvent::RunItemsDeliveryFault { .. }
            | ShellEvent::Scan(ScanEvent::Stage(_))
            | ShellEvent::OperatorQuestion(_)
            | ShellEvent::OperatorQuestionCompleted(_)
            | ShellEvent::CredentialQuestionRouted { .. } => false,
            ShellEvent::Scan(ScanEvent::Finished { .. } | ScanEvent::Failed { .. }) => {
                !self.tool_is_running() && self.scan().is_some_and(|scan| scan.running)
            }
            ShellEvent::Tool(
                ToolEvent::Finished { .. }
                | ToolEvent::Failed { .. }
                | ToolEvent::Refused { .. }
                | ToolEvent::ObservedFinished { .. }
                | ToolEvent::ObservedFailed { .. }
                | ToolEvent::ObservedRefused { .. }
                | ToolEvent::AuthenticationFailed { .. },
            ) => !self.scan().is_some_and(|scan| scan.running),
            ShellEvent::Agent(_) | ShellEvent::Plan(_) | ShellEvent::Threat(_) => {
                event.is_terminal()
            }
        }
    }

    fn apply_operator_question(&mut self, envelope: OperatorQuestionEnvelope) {
        let matches_run = self
            .activity()
            .is_some_and(|session| session.run_id == envelope.request.run_id);
        if !matches_run {
            let mut card = PendingOperatorQuestion::new(envelope);
            card.cancel();
            return;
        }
        self.record_operator_questions(&envelope);
        let backgrounded = self
            .activity()
            .is_some_and(|session| session.run_focus_backgrounded);
        if let Some(session) = self.activity_mut() {
            session.record_operator_question();
            session.operator_answer_acknowledgement = None;
            session.operator_question = Some(PendingOperatorQuestion::new(envelope));
        }
        self.log("agent", "WAITING INPUT — open Activity to answer");
        if !backgrounded {
            self.set_shell_view(ShellView::Activity);
            self.set_input_mode(InputMode::Navigate);
        }
    }

    fn record_operator_questions(&mut self, envelope: &OperatorQuestionEnvelope) {
        for question in &envelope.request.questions {
            self.record_session_event(
                kuzushi_core::session_transcript::SessionEvent::OperatorQuestion {
                    question_id: question.id.clone(),
                    kind: "operator".to_string(),
                    prompt: Some(question.prompt.clone()),
                },
            );
        }
    }

    fn apply_operator_question_completed(&mut self, completed: OperatorQuestionCompleted) {
        let matches_run = self
            .activity()
            .is_some_and(|session| session.run_id == completed.run_id);
        if !matches_run {
            return;
        }
        self.record_operator_answer(&completed);
        if !self.clear_matching_operator_question(&completed.request_id) {
            return;
        }
        self.log(
            "agent",
            operator_question_completion_detail(completed.outcome),
        );
        self.surface_operator_question_completion(&completed);
    }

    fn record_operator_answer(&mut self, completed: &OperatorQuestionCompleted) {
        self.record_session_event(
            kuzushi_core::session_transcript::SessionEvent::OperatorAnswer {
                question_id: completed.request_id.clone(),
                kind: "operator".to_string(),
                outcome: operator_question_outcome_label(completed.outcome).to_string(),
                answer: operator_question_answer_summary(completed),
            },
        );
    }

    fn clear_matching_operator_question(&mut self, request_id: &str) -> bool {
        let should_clear = self
            .activity()
            .and_then(|session| session.operator_question.as_ref())
            .is_some_and(|card| card.request().request_id == request_id);
        if !should_clear {
            return false;
        }
        if let Some(session) = self.activity_mut() {
            session.operator_question = None;
        }
        true
    }

    fn surface_operator_question_completion(&mut self, completed: &OperatorQuestionCompleted) {
        match completed.outcome {
            OperatorQuestionOutcome::Submitted => {
                let acknowledgement = submitted_operator_answer_notice(completed);
                self.remember_operator_answer_acknowledgement(&acknowledgement);
                self.set_success_notice("answer", acknowledgement)
            }
            OperatorQuestionOutcome::AutoResolved => {
                let acknowledgement = "recommended answer accepted · run resumed";
                self.remember_operator_answer_acknowledgement(acknowledgement);
                self.set_info_notice("answer", acknowledgement)
            }
            _ => {}
        }
    }

    fn remember_operator_answer_acknowledgement(&mut self, acknowledgement: &str) {
        if let Some(session) = self.activity_mut() {
            session.operator_answer_acknowledgement = Some(acknowledgement.to_string());
        }
    }

    fn apply_credential_question_route(
        &mut self,
        request_id: &str,
        run_id: &str,
    ) -> Vec<ShellEffect> {
        if !self
            .activity()
            .is_some_and(|session| session.run_id == run_id)
        {
            return Vec::new();
        }
        self.record_credential_question_route(request_id);
        self.log(
            "agent",
            format!(
                "credential question {request_id} was refused — secret entry moved to Setup/Auth"
            ),
        );
        self.reduce_auth_status()
    }

    fn record_credential_question_route(&mut self, request_id: &str) {
        self.record_session_event(
            kuzushi_core::session_transcript::SessionEvent::OperatorQuestion {
                question_id: request_id.to_string(),
                kind: "credential".to_string(),
                prompt: None,
            },
        );
        self.record_session_event(
            kuzushi_core::session_transcript::SessionEvent::OperatorAnswer {
                question_id: request_id.to_string(),
                kind: "credential".to_string(),
                outcome: "routed_to_setup".to_string(),
                answer: None,
            },
        );
    }

    fn clear_finished_job(&mut self, kind: JobKind) {
        match kind {
            JobKind::Run => self.clear_finished_run_job(),
            JobKind::Agent => self.clear_finished_agent_job(),
            JobKind::Plan => self.clear_finished_plan_job(),
            JobKind::Threat => self.clear_finished_threat_job(),
        }
    }

    fn clear_finished_run_job(&mut self) {
        if self.scan().is_some_and(|scan| scan.running) || self.tool_is_running() {
            return;
        }
        self.set_scan_cancel(None);
        self.clear_finished_tool_run_slot();
    }

    fn clear_finished_agent_job(&mut self) {
        if self.agent_chat().is_some_and(|agent| agent.running) {
            return;
        }
        self.set_agent_cancel(None);
    }

    fn clear_finished_plan_job(&mut self) {
        if self.planner_running() {
            return;
        }
        self.set_plan_cancel(None);
    }

    fn clear_finished_threat_job(&mut self) {
        if self.threat_worker_running() {
            return;
        }
        self.set_threat_cancel(None);
    }
}

fn durable_phase_receipt_prefix(
    target: &std::path::Path,
    receipt: &kuzushi_core::run_lifecycle::RunItemEnvelopeV1,
    applied_seq: u64,
) -> anyhow::Result<Vec<kuzushi_core::run_lifecycle::RunItemEnvelopeV1>> {
    use kuzushi_core::run_lifecycle::ProjectionHealth;
    let read = kuzushi_core::run_lifecycle::read_run_items(target, receipt.run_id.as_str())?
        .ok_or_else(|| anyhow::anyhow!("durable typed stream is missing"))?;
    anyhow::ensure!(
        read.health == ProjectionHealth::Healthy,
        "durable typed stream is degraded"
    );
    anyhow::ensure!(
        read.items.iter().any(|item| {
            item.item_id == receipt.item_id && item.event_hash == receipt.event_hash
        }),
        "durable typed stream does not contain the committed receipt"
    );
    Ok(read
        .items
        .into_iter()
        .filter(|item| item.seq > applied_seq && item.seq <= receipt.seq)
        .collect())
}

fn operator_question_outcome_label(outcome: OperatorQuestionOutcome) -> &'static str {
    match outcome {
        OperatorQuestionOutcome::Submitted => "submitted",
        OperatorQuestionOutcome::AutoResolved => "auto_resolved",
        OperatorQuestionOutcome::Canceled => "canceled",
        OperatorQuestionOutcome::RoutedToSetup => "routed_to_setup",
        OperatorQuestionOutcome::Failed => "failed",
    }
}

fn submitted_operator_answer_notice(completed: &OperatorQuestionCompleted) -> String {
    let mut accepted = completed.selected_labels.clone();
    if completed.freeform_supplied {
        accepted.push("free-form answer".to_string());
    }
    if accepted.is_empty() {
        return "answer accepted · run resumed".to_string();
    }
    format!("accepted {} · run resumed", accepted.join(", "))
}

fn operator_question_answer_summary(completed: &OperatorQuestionCompleted) -> Option<String> {
    if completed.selected_labels.is_empty() {
        return completed
            .freeform_supplied
            .then(|| "freeform answer supplied".to_string());
    }
    Some(completed.selected_labels.join(", "))
}

fn operator_question_completion_detail(outcome: OperatorQuestionOutcome) -> &'static str {
    match outcome {
        OperatorQuestionOutcome::Submitted => "operator answer accepted — run resumed",
        OperatorQuestionOutcome::AutoResolved => "operator question auto-resolved — run resumed",
        OperatorQuestionOutcome::Canceled => {
            "operator question canceled — run resumed without an answer"
        }
        OperatorQuestionOutcome::RoutedToSetup => "credential question routed to Setup/Auth",
        OperatorQuestionOutcome::Failed => "operator question failed",
    }
}

#[cfg(test)]
mod receipt_notice_tests;

#[cfg(test)]
mod operator_answer_notice_tests {
    use super::*;

    #[test]
    fn freeform_acknowledgement_never_contains_answer_text() {
        let completed = OperatorQuestionCompleted {
            request_id: "question-1".to_string(),
            run_id: "run-1".to_string(),
            outcome: OperatorQuestionOutcome::Submitted,
            selected_labels: Vec::new(),
            freeform_supplied: true,
        };

        assert_eq!(
            submitted_operator_answer_notice(&completed),
            "accepted free-form answer · run resumed"
        );
    }

    #[test]
    fn submitted_answer_surfaces_an_immediate_success_notice() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_activity(Some(crate::ActivitySession::new("run-1")));
        let completed = OperatorQuestionCompleted {
            request_id: "question-1".to_string(),
            run_id: "run-1".to_string(),
            outcome: OperatorQuestionOutcome::Submitted,
            selected_labels: vec!["Repository".to_string()],
            freeform_supplied: false,
        };

        app.surface_operator_question_completion(&completed);

        let notice = app.advisory().notice.as_ref().expect("answer notice");
        assert_eq!(notice.severity, crate::NoticeSeverity::Success);
        assert_eq!(notice.message, "accepted Repository · run resumed");
        assert_eq!(
            app.activity()
                .and_then(|session| session.operator_answer_acknowledgement.as_deref()),
            Some("accepted Repository · run resumed")
        );
    }

    #[test]
    fn final_run_receipt_retains_the_answer_acknowledgement() {
        let mut session = crate::ActivitySession::new("run-1");
        session.mark_run_focus_terminal_pending("completed");
        let receipt = session.run_focus_receipt.as_ref().expect("run receipt");

        let notice = run_receipt_notice(receipt, Some("accepted Repository · run resumed"));

        assert!(notice.contains("run receipt · completed"), "{notice}");
        assert!(notice.contains("accepted Repository"), "{notice}");
    }
}

fn completed_with_attempt_id(
    completed: kuzushi_core::workflow_attempts::PhaseAttemptCompleted,
    attempt_id: Option<&str>,
) -> kuzushi_core::workflow_attempts::PhaseAttemptCompleted {
    match attempt_id {
        Some(attempt_id) => completed.with_attempt_id(attempt_id),
        None => completed,
    }
}

fn completed_with_map_blocker(
    completed: kuzushi_core::workflow_attempts::PhaseAttemptCompleted,
    target: &std::path::Path,
    phase: WorkflowPhase,
    run_refs: &[String],
) -> kuzushi_core::workflow_attempts::PhaseAttemptCompleted {
    match map_evidence_blocker(target, phase, run_refs, completed.outcome) {
        Some(reason) => completed.with_selection_blocked(reason),
        None => completed,
    }
}

fn completed_with_lineage(
    completed: kuzushi_core::workflow_attempts::PhaseAttemptCompleted,
    lineage: Option<(
        String,
        kuzushi_core::workflow_attempts::PhaseAttemptDerivation,
    )>,
) -> kuzushi_core::workflow_attempts::PhaseAttemptCompleted {
    match lineage {
        Some((parent, derivation)) => completed.derived_from(parent, derivation),
        None => completed,
    }
}

fn completed_with_live_health_gate(
    mut completed: kuzushi_core::workflow_attempts::PhaseAttemptCompleted,
    target: Option<&std::path::Path>,
    session: Option<&ActivitySession>,
) -> kuzushi_core::workflow_attempts::PhaseAttemptCompleted {
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;
    let final_run = completed.run_refs.last().map(String::as_str);
    let matching = session.filter(|session| Some(session.run_id.as_str()) == final_run);
    if matching.is_none_or(|session| run_allows_phase_completion(target, final_run, session)) {
        return completed;
    }
    if completed.outcome == PhaseAttemptOutcome::Completed {
        completed.outcome = PhaseAttemptOutcome::Partial;
    }
    if completed.outcome != PhaseAttemptOutcome::Partial {
        return completed;
    }
    // A healthy, durable run whose terminal is partial carries honest
    // partial evidence — the operator may accept it explicitly. Only a
    // genuinely unsettled run (integrity or durability) blocks selection.
    if matching.is_some_and(run_settlement_is_healthy_and_durable) {
        return completed;
    }
    completed.selection_blocked_reason = Some(
        "live run settlement is not healthy and durable; inspect the run before continuing"
            .to_string(),
    );
    completed
}

fn run_settlement_is_healthy_and_durable(session: &ActivitySession) -> bool {
    use kuzushi_core::run_lifecycle::{ProjectionHealth, RunDurabilityHealth};
    let health = session.effective_run_lifecycle_health();
    matches!(health.integrity, ProjectionHealth::Healthy)
        && matches!(health.durability, RunDurabilityHealth::Durable { .. })
}

fn live_health_adjusted_outcome(
    target: Option<&std::path::Path>,
    outcome: kuzushi_core::workflow_attempts::PhaseAttemptOutcome,
    run_refs: &[String],
    session: Option<&ActivitySession>,
) -> kuzushi_core::workflow_attempts::PhaseAttemptOutcome {
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;
    if outcome != PhaseAttemptOutcome::Completed {
        return outcome;
    }
    let final_run = run_refs.last().map(String::as_str);
    let matching = session.filter(|session| Some(session.run_id.as_str()) == final_run);
    if matching.is_some_and(|session| !run_allows_phase_completion(target, final_run, session)) {
        PhaseAttemptOutcome::Partial
    } else {
        outcome
    }
}

fn run_allows_phase_completion(
    target: Option<&std::path::Path>,
    run_id: Option<&str>,
    session: &ActivitySession,
) -> bool {
    run_settlement_is_healthy_and_durable(session)
        && (live_terminal_is_complete(session) || durable_terminal_is_complete(target.zip(run_id)))
}

fn live_terminal_is_complete(session: &ActivitySession) -> bool {
    use kuzushi_core::run_lifecycle::RunItemStatus;
    matches!(
        session
            .run_projection
            .terminal
            .as_ref()
            .map(|item| item.status),
        Some(RunItemStatus::Completed | RunItemStatus::Skipped)
    )
}

fn durable_terminal_is_complete(run: Option<(&std::path::Path, &str)>) -> bool {
    use kuzushi_core::run_lifecycle::{ProjectionHealth, RunItemStatus, RunProjectionSource};
    let Some((target, run_id)) = run else {
        return false;
    };
    kuzushi_core::run_lifecycle::load_run_projection(target, run_id)
        .ok()
        .is_some_and(|read| {
            read.source == RunProjectionSource::TypedV1
                && read.projection.health == ProjectionHealth::Healthy
                && matches!(
                    read.projection.terminal.map(|terminal| terminal.status),
                    Some(RunItemStatus::Completed | RunItemStatus::Skipped)
                )
        })
}

fn phase_result_routes_to_report(
    app: &ShellApp,
    receipt: &RunFocusReceipt,
    phase: WorkflowPhase,
) -> bool {
    match phase {
        WorkflowPhase::Scan => receipt.changed_findings == 0,
        WorkflowPhase::Review | WorkflowPhase::Prove => crate::ui_view_models::journey_model(app)
            .is_some_and(|journey| {
                matches!(
                    journey.destination,
                    crate::ui_view_models::JourneyDestination::Report(_)
                )
            }),
        WorkflowPhase::Map | WorkflowPhase::Fix => false,
    }
}

fn durable_phase_attempt_outcome(
    target: &std::path::Path,
    phase: WorkflowPhase,
    run_refs: &[String],
    fallback: &str,
) -> kuzushi_core::workflow_attempts::PhaseAttemptOutcome {
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;

    if final_typed_run_is_blocked(target, run_refs) {
        return PhaseAttemptOutcome::Blocked;
    }
    let fallback = phase_attempt_outcome_from_label(fallback);
    outcome_from_phase_evidence(target, phase, run_refs, fallback)
}

fn outcome_from_phase_evidence(
    target: &std::path::Path,
    phase: WorkflowPhase,
    run_refs: &[String],
    fallback: kuzushi_core::workflow_attempts::PhaseAttemptOutcome,
) -> kuzushi_core::workflow_attempts::PhaseAttemptOutcome {
    if recovery_only_outcome(fallback) {
        return fallback;
    }
    match phase {
        WorkflowPhase::Map => map_phase_attempt_outcome(target, run_refs),
        WorkflowPhase::Scan => scan_phase_attempt_outcome(target, run_refs, fallback),
        WorkflowPhase::Review | WorkflowPhase::Prove | WorkflowPhase::Fix => fallback,
    }
}

fn recovery_only_outcome(outcome: kuzushi_core::workflow_attempts::PhaseAttemptOutcome) -> bool {
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;

    matches!(
        outcome,
        PhaseAttemptOutcome::Blocked | PhaseAttemptOutcome::Failed | PhaseAttemptOutcome::Canceled
    )
}

fn map_phase_attempt_outcome(
    target: &std::path::Path,
    run_refs: &[String],
) -> kuzushi_core::workflow_attempts::PhaseAttemptOutcome {
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;

    let facts = kuzushi_core::workflow_attempts::collect_map_evidence(target, run_refs);
    if kuzushi_core::workflow_attempts::assess_map_evidence(&facts).is_adequate() {
        PhaseAttemptOutcome::Completed
    } else {
        PhaseAttemptOutcome::Partial
    }
}

fn scan_phase_attempt_outcome(
    target: &std::path::Path,
    run_refs: &[String],
    fallback: kuzushi_core::workflow_attempts::PhaseAttemptOutcome,
) -> kuzushi_core::workflow_attempts::PhaseAttemptOutcome {
    run_refs
        .iter()
        .filter_map(|run_id| {
            kuzushi_core::run_artifacts::load_scan_stage_data(target, run_id)
                .ok()
                .flatten()
                .map(|receipt| receipt.outcome)
        })
        .reduce(merge_phase_stage_outcome)
        .map(phase_stage_attempt_outcome)
        .unwrap_or(fallback)
}

fn final_typed_run_is_blocked(target: &std::path::Path, run_refs: &[String]) -> bool {
    use kuzushi_core::run_lifecycle::{ProjectionHealth, RunItemStatus, RunProjectionSource};

    run_refs
        .last()
        .and_then(|run_id| kuzushi_core::run_lifecycle::load_run_projection(target, run_id).ok())
        .is_some_and(|read| {
            read.source == RunProjectionSource::TypedV1
                && read.projection.health == ProjectionHealth::Healthy
                && read
                    .projection
                    .terminal
                    .is_some_and(|terminal| terminal.status == RunItemStatus::Blocked)
        })
}

fn map_evidence_blocker(
    target: &std::path::Path,
    phase: WorkflowPhase,
    run_refs: &[String],
    outcome: kuzushi_core::workflow_attempts::PhaseAttemptOutcome,
) -> Option<String> {
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;

    if phase != WorkflowPhase::Map || outcome != PhaseAttemptOutcome::Partial {
        return None;
    }
    let facts = kuzushi_core::workflow_attempts::collect_map_evidence(target, run_refs);
    (!kuzushi_core::workflow_attempts::assess_map_evidence(&facts).is_adequate())
        .then(|| kuzushi_core::workflow_attempts::insufficient_map_evidence_message(target))
}

fn apply_map_evidence_blocker(receipt: &mut RunFocusReceipt, blocker: Option<String>) {
    use kuzushi_core::workflow_attempts::PhaseResultAction;

    let Some(blocker) = blocker else {
        return;
    };
    receipt.actions = vec![
        PhaseResultAction::Open,
        PhaseResultAction::RunAgain,
        PhaseResultAction::Discard,
    ];
    receipt.recommended_next = Some(blocker);
}

fn phase_attempt_outcome_label(
    outcome: kuzushi_core::workflow_attempts::PhaseAttemptOutcome,
) -> &'static str {
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;

    match outcome {
        PhaseAttemptOutcome::Completed => "completed",
        PhaseAttemptOutcome::Partial => "partial",
        PhaseAttemptOutcome::Blocked => "blocked",
        PhaseAttemptOutcome::Failed => "failed",
        PhaseAttemptOutcome::Canceled => "canceled",
    }
}

fn merge_phase_stage_outcome(
    current: kuzushi_core::run_artifacts::PhaseStageOutcome,
    next: kuzushi_core::run_artifacts::PhaseStageOutcome,
) -> kuzushi_core::run_artifacts::PhaseStageOutcome {
    use kuzushi_core::run_artifacts::PhaseStageOutcome::{Completed, Failed, Partial, Skipped};

    match (current, next) {
        (Failed, _) | (_, Failed) => Failed,
        (Partial | Skipped, _) | (_, Partial | Skipped) => Partial,
        (Completed, Completed) => Completed,
    }
}

fn phase_stage_attempt_outcome(
    outcome: kuzushi_core::run_artifacts::PhaseStageOutcome,
) -> kuzushi_core::workflow_attempts::PhaseAttemptOutcome {
    use kuzushi_core::run_artifacts::PhaseStageOutcome;
    use kuzushi_core::workflow_attempts::PhaseAttemptOutcome;

    match outcome {
        PhaseStageOutcome::Completed => PhaseAttemptOutcome::Completed,
        PhaseStageOutcome::Partial | PhaseStageOutcome::Skipped => PhaseAttemptOutcome::Partial,
        PhaseStageOutcome::Failed => PhaseAttemptOutcome::Failed,
    }
}

fn terminal_descriptor_run_tool(summary: &kuzushi_core::RunSummary) -> Option<&str> {
    if !matches!(summary.kind.as_str(), "tool" | "scan") {
        return None;
    }
    if !terminal_run_status(&summary.status) {
        return None;
    }
    summary.tool.as_deref()
}

fn terminal_run_status(status: &str) -> bool {
    !matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "" | "running" | "queued" | "started"
    )
}

fn nested_run_refs(target: &std::path::Path, run_refs: &[String]) -> Vec<String> {
    run_refs
        .iter()
        .flat_map(|run_id| nested_result_run_refs(target, run_id))
        .collect()
}

fn extend_unique_run_refs(run_refs: &mut Vec<String>, nested: Vec<String>) {
    for run_id in nested {
        if !run_refs.contains(&run_id) {
            run_refs.push(run_id);
        }
    }
}

fn receipt_run_changes(
    target: &std::path::Path,
    run_refs: &[String],
) -> (u64, std::collections::BTreeSet<String>) {
    run_refs
        .iter()
        .filter_map(|run_id| kuzushi_core::load_run_summary(target, run_id).ok())
        .fold(
            (0, std::collections::BTreeSet::new()),
            |(findings, mut artifacts), summary| {
                artifacts.extend(summary.artifacts.into_iter().map(|artifact| artifact.path));
                (
                    findings.max(summary.findings.unwrap_or_default()),
                    artifacts,
                )
            },
        )
}

fn receipt_run_result_summaries(
    target: &std::path::Path,
    run_refs: &[String],
) -> (
    Vec<kuzushi_core::run_artifacts::RunResultSummary>,
    kuzushi_core::run_lifecycle::RunPresentationHydrationV1,
    Vec<String>,
) {
    let mut summaries = Vec::new();
    let mut hydration = kuzushi_core::run_lifecycle::RunPresentationHydrationV1::default();
    let mut issues = Vec::new();
    for run_id in run_refs {
        match receipt_run_result_summary(target, run_id) {
            Ok(result) => {
                summaries.extend(result.summaries);
                hydration.merge(result.hydration);
            }
            Err(issue) => issues.push(issue),
        }
    }
    (summaries, hydration, issues)
}

struct ReceiptResultHydration {
    summaries: Vec<kuzushi_core::run_artifacts::RunResultSummary>,
    hydration: kuzushi_core::run_lifecycle::RunPresentationHydrationV1,
}

fn receipt_run_result_summary(
    target: &std::path::Path,
    run_id: &str,
) -> Result<ReceiptResultHydration, String> {
    let read = kuzushi_core::run_lifecycle::load_run_projection(target, run_id)
        .map_err(|error| format!("Could not load semantic projection for run {run_id}: {error}"))?;
    if read.source == kuzushi_core::run_lifecycle::RunProjectionSource::TypedV1 {
        return Ok(ReceiptResultHydration {
            summaries: read.presentation_hydration.verified_summaries(),
            hydration: read.presentation_hydration,
        });
    }
    let summary =
        kuzushi_core::run_artifacts::load_run_result_summary(target, run_id).map_err(|error| {
            format!("Could not summarize terminal result for run {run_id}: {error}")
        })?;
    Ok(ReceiptResultHydration {
        summaries: summary.into_iter().collect(),
        hydration: Default::default(),
    })
}

fn nested_result_run_refs(target: &std::path::Path, run_id: &str) -> Vec<String> {
    let kuzushi_core::RunArtifactRead::Ready { value, .. } =
        kuzushi_core::read_run_artifact_text(target, run_id, "result.json")
    else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&value) else {
        return Vec::new();
    };
    let Some(run_ids) = value.get("data").and_then(|data| data.get("runIds")) else {
        return Vec::new();
    };
    let mut refs = Vec::new();
    collect_result_run_refs(run_ids, &mut refs);
    refs
}

fn collect_result_run_refs(value: &serde_json::Value, refs: &mut Vec<String>) {
    if let Some(run_id) = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        push_unique_run_ref(refs, run_id);
        return;
    }
    if let Some(values) = value.as_array() {
        values
            .iter()
            .for_each(|value| collect_result_run_refs(value, refs));
        return;
    }
    value
        .as_object()
        .into_iter()
        .flat_map(|values| values.values())
        .for_each(|value| collect_result_run_refs(value, refs));
}

fn push_unique_run_ref(refs: &mut Vec<String>, run_id: &str) {
    if !refs.iter().any(|existing| existing == run_id) {
        refs.push(run_id.to_string());
    }
}

fn run_focus_event_outcome(event: &ShellEvent) -> String {
    match event {
        ShellEvent::Scan(ScanEvent::Finished { result })
        | ShellEvent::Tool(ToolEvent::Finished { result, .. })
        | ShellEvent::Tool(ToolEvent::ObservedFinished { result, .. }) => {
            match kuzushi_core::tool_result_status(result) {
                kuzushi_core::ToolResultStatus::Completed => "completed",
                kuzushi_core::ToolResultStatus::Partial => "partial",
                kuzushi_core::ToolResultStatus::Skipped => "skipped",
                kuzushi_core::ToolResultStatus::Failed => "failed",
            }
        }
        ShellEvent::Tool(ToolEvent::Refused { .. } | ToolEvent::ObservedRefused { .. }) => "blocked",
        ShellEvent::Scan(ScanEvent::Failed { .. })
        | ShellEvent::Tool(ToolEvent::Failed { .. })
        | ShellEvent::Tool(ToolEvent::ObservedFailed { .. })
        | ShellEvent::Tool(ToolEvent::AuthenticationFailed { .. })
        | ShellEvent::Agent(AgentEvent::Failed { .. })
        | ShellEvent::Plan(PlanEvent::Failed { .. })
        | ShellEvent::Threat(ThreatPatchEvent::Failed { .. }) => "failed",
        ShellEvent::Agent(AgentEvent::Answered { .. })
        | ShellEvent::Plan(PlanEvent::Proposed { .. })
        | ShellEvent::Threat(ThreatPatchEvent::Proposed { .. } | ThreatPatchEvent::Answer { .. }) => {
            "completed"
        }
        ShellEvent::Agent(AgentEvent::ResponseText(_))
        | ShellEvent::RunItem(_)
        | ShellEvent::RunItemsDurable { .. }
        | ShellEvent::RunItemsDerivativesApplied { .. }
        | ShellEvent::RunItemsFault { .. }
        | ShellEvent::RunItemsDeliveryFault { .. }
        | ShellEvent::Scan(ScanEvent::Stage(_))
        | ShellEvent::OperatorQuestion(_)
        | ShellEvent::OperatorQuestionCompleted(_)
        | ShellEvent::CredentialQuestionRouted { .. } => "running",
    }
    .to_string()
}

#[cfg(test)]
mod run_focus_completion_tests {
    use super::*;
    use kuzushi_core::run_artifacts::{
        PhaseStageOutcome, PhaseStageReceipt, ScanFindingDelta, ScanStageData, ScanStagePlan,
        ScanStageScope, SAST_PHASE_STAGES_JSONL_FILE,
    };
    use kuzushi_core::workflow_attempts::{
        PhaseAttemptOutcome, PhaseResultAction, PhaseTargetSnapshot,
    };

    #[test]
    fn lifecycle_delivery_events_update_orthogonal_health_axes() {
        use kuzushi_core::run_lifecycle::{
            CommittedRange, PersistenceFailureStage, RunDeliveryHealth, RunDurabilityHealth,
            RunItemWriterFault, SafeText,
        };
        let mut app = ShellApp::new(V2Config::default(), None);
        app.apply_current_job_event(ShellEvent::RunItemsDurable {
            run_id: "run-delivery".to_string(),
            range: CommittedRange {
                first_seq: 1,
                through_seq: 3,
            },
        });
        app.apply_current_job_event(ShellEvent::RunItemsFault {
            run_id: "run-delivery".to_string(),
            fault: RunItemWriterFault {
                stage: PersistenceFailureStage::Sync,
                last_durable_seq: 3,
                detail: SafeText::operator_visible("sync failed"),
                execution_may_have_occurred: true,
            },
        });

        let health = app.activity().unwrap().effective_run_lifecycle_health();
        assert_eq!(
            health.delivery,
            RunDeliveryHealth::CatchingUp {
                applied_seq: 0,
                durable_seq: 3,
            }
        );
        assert!(matches!(
            health.durability,
            RunDurabilityHealth::Failed {
                last_durable_seq: 3,
                execution_may_have_occurred: true,
                ..
            }
        ));
    }

    #[test]
    fn delivery_fault_does_not_forge_integrity_or_durability_failure() {
        use kuzushi_core::run_lifecycle::{
            CommittedRange, ProjectionHealth, RunDeliveryHealth, RunDurabilityHealth,
            RunItemDeliveryFailureStage, RunItemDeliveryFault, SafeText,
        };
        let mut app = ShellApp::new(V2Config::default(), None);
        app.apply_current_job_event(ShellEvent::RunItemsDurable {
            run_id: "run-delivery-fault".to_string(),
            range: CommittedRange {
                first_seq: 1,
                through_seq: 2,
            },
        });
        app.apply_current_job_event(ShellEvent::RunItemsDeliveryFault {
            run_id: "run-delivery-fault".to_string(),
            fault: RunItemDeliveryFault {
                stage: RunItemDeliveryFailureStage::ItemSubscriber,
                applied_seq: 0,
                durable_seq: 2,
                detail: SafeText::operator_visible("item subscriber failed"),
            },
        });

        let health = app.activity().unwrap().effective_run_lifecycle_health();
        assert_eq!(health.integrity, ProjectionHealth::Healthy);
        assert_eq!(
            health.durability,
            RunDurabilityHealth::Durable { through_seq: 2 }
        );
        assert!(matches!(
            health.delivery,
            RunDeliveryHealth::Failed {
                applied_seq: 0,
                stage: RunItemDeliveryFailureStage::ItemSubscriber,
                ref detail,
            } if detail.as_str().contains("subscriber failed")
        ));
    }

    #[test]
    fn live_writer_fault_forces_completed_attempt_to_partial_inspection() {
        use kuzushi_core::run_lifecycle::{PersistenceFailureStage, RunItemWriterFault, SafeText};
        let mut session = completed_live_session("run-unsettled");
        session.record_run_item_writer_fault(RunItemWriterFault {
            stage: PersistenceFailureStage::Sync,
            last_durable_seq: 1,
            detail: SafeText::operator_visible("terminal sync failed"),
            execution_may_have_occurred: true,
        });
        let completed = completed_attempt("run-unsettled");
        let adjusted = live_health_adjusted_outcome(
            None,
            PhaseAttemptOutcome::Completed,
            &["run-unsettled".to_string()],
            Some(&session),
        );

        let gated = completed_with_live_health_gate(completed, None, Some(&session));

        assert_eq!(adjusted, PhaseAttemptOutcome::Partial);
        assert_eq!(gated.outcome, PhaseAttemptOutcome::Partial);
        assert!(gated
            .selection_blocked_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("inspect the run")));
    }

    /// A healthy, durable run whose terminal is PARTIAL is honest partial
    /// evidence — the operator must stay able to select it. Blocking is
    /// reserved for genuine settlement failures (integrity/durability).
    #[test]
    fn healthy_partial_terminal_stays_selectable() {
        let mut session = ActivitySession::new("run-partial-healthy");
        session.observe_committed_range(kuzushi_core::run_lifecycle::CommittedRange {
            first_seq: 1,
            through_seq: 1,
        });
        session
            .apply_run_item(partial_terminal_item("run-partial-healthy"))
            .unwrap();
        let mut completed = completed_attempt("run-partial-healthy");
        completed.outcome = PhaseAttemptOutcome::Partial;

        let gated = completed_with_live_health_gate(completed, None, Some(&session));

        assert_eq!(gated.outcome, PhaseAttemptOutcome::Partial);
        assert!(
            gated.selection_blocked_reason.is_none(),
            "healthy partial evidence must not be selection-blocked: {:?}",
            gated.selection_blocked_reason
        );
    }

    fn partial_terminal_item(run_id: &str) -> kuzushi_core::run_lifecycle::RunItemEnvelopeV1 {
        use kuzushi_core::run_lifecycle::{
            RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemStatus, RunItemV1, SafeText,
            WorkflowContinuation,
        };
        RunItemEnvelopeV1::new(
            1,
            RunId::parse(run_id).unwrap(),
            RunItemId::new(),
            RunItemSource::Workflow,
            RunItemV1::TerminalOutcome {
                status: RunItemStatus::Partial,
                summary: SafeText::operator_visible("partial"),
                cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("partial evidence recorded"),
                },
            },
            None,
        )
        .unwrap()
    }

    #[test]
    fn stale_run_item_cannot_mutate_the_current_run_focus_projection() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_activity(Some(ActivitySession::new("run-current")));

        app.apply_current_job_event(ShellEvent::RunItem(partial_terminal_item("run-stale")));

        let session = app.activity().unwrap();
        assert_eq!(session.run_id, "run-current");
        assert!(session.run_projection.terminal.is_none());
        assert!(app.log_lines().iter().any(|line| {
            line.prefix == "run"
                && line
                    .body
                    .contains("ignored stale lifecycle item for run run-stale")
        }));
    }

    #[test]
    fn first_run_item_creates_a_session_with_its_real_run_id() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.apply_current_job_event(ShellEvent::RunItem(partial_terminal_item("run-real")));

        assert_eq!(app.activity().unwrap().run_id, "run-real");
    }

    #[test]
    fn tool_cancel_request_marks_new_run_items_canceling_without_a_scan() {
        use kuzushi_core::run_lifecycle::{
            RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemStatus, RunItemV1,
            RunTaskId, SafeText,
        };
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_tool_abort_requested_for_test(true);
        let task_id = RunTaskId::new();
        let item = RunItemEnvelopeV1::new(
            1,
            RunId::parse("run-canceling").unwrap(),
            RunItemId::new(),
            RunItemSource::Workflow,
            RunItemV1::TaskUpdated {
                title: SafeText::operator_visible("active task"),
                status: RunItemStatus::Running,
                detail: None,
            },
            None,
        )
        .unwrap()
        .with_task(task_id)
        .unwrap();

        app.apply_current_job_event(ShellEvent::RunItem(item));

        assert_eq!(
            app.activity().unwrap().tasks[&task_id.to_string()].state,
            crate::DagTaskState::Canceling
        );
    }

    #[test]
    fn derivative_only_failure_does_not_block_phase_completion() {
        use kuzushi_core::run_lifecycle::{
            RunItemDeliveryFailureStage, RunItemDeliveryFault, SafeText,
        };
        let mut session = completed_live_session("run-derivative-only");
        session.record_run_item_delivery_fault(RunItemDeliveryFault {
            stage: RunItemDeliveryFailureStage::StorageProjection,
            applied_seq: 0,
            durable_seq: 1,
            detail: SafeText::operator_visible("compatibility projection failed"),
        });
        let completed = completed_attempt("run-derivative-only");
        let adjusted = live_health_adjusted_outcome(
            None,
            PhaseAttemptOutcome::Completed,
            &["run-derivative-only".to_string()],
            Some(&session),
        );

        let gated = completed_with_live_health_gate(completed, None, Some(&session));

        assert_eq!(adjusted, PhaseAttemptOutcome::Completed);
        assert_eq!(gated.outcome, PhaseAttemptOutcome::Completed);
        assert!(gated.selection_blocked_reason.is_none());
    }

    #[test]
    fn credential_route_records_only_routing_and_outcome() {
        let temp = tempfile::tempdir().unwrap();
        let store = kuzushi_core::session_transcript::SessionTranscriptStore::from_root(
            temp.path().join("sessions"),
        );
        let recorder = store
            .start(kuzushi_core::session_transcript::SessionMetadata::new(
                "scripted",
                temp.path(),
            ))
            .unwrap();
        let session_id = recorder.session_id().to_string();
        let mut app = ShellApp::with_registry_and_transcript(
            V2Config::default(),
            None,
            ModuleRegistry::with_v2_builtins(),
            Some(recorder),
        );
        app.set_activity(Some(ActivitySession::new("run-credential")));

        app.apply_credential_question_route("credential-q", "run-credential");
        app.finish_session_transcript("completed");

        let read = store.read(&session_id).unwrap();
        let records = read
            .records
            .iter()
            .filter(|record| {
                matches!(
                    record.event_type.as_str(),
                    "operator_question" | "operator_answer"
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| {
            record
                .payload
                .get("prompt")
                .or_else(|| record.payload.get("answer"))
                .is_none_or(serde_json::Value::is_null)
        }));
    }

    #[test]
    fn durable_partial_scan_stage_overrides_completed_activity_fallback() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "partial-composite-scan";
        write_scan_stage(target.path(), run_id, PhaseStageOutcome::Partial);

        assert_eq!(
            durable_phase_attempt_outcome(
                target.path(),
                WorkflowPhase::Scan,
                &[run_id.to_string()],
                "completed",
            ),
            PhaseAttemptOutcome::Partial
        );
    }

    #[test]
    fn typed_blocked_terminal_overrides_success_fallback_and_phase_evidence() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "blocked-phase-run";
        write_terminal_run(
            target.path(),
            run_id,
            kuzushi_core::run_lifecycle::RunItemStatus::Blocked,
        );

        assert_eq!(
            durable_phase_attempt_outcome(
                target.path(),
                WorkflowPhase::Map,
                &[run_id.to_string()],
                "completed",
            ),
            PhaseAttemptOutcome::Blocked
        );
    }

    #[test]
    fn durable_scan_stage_aggregation_uses_the_most_severe_outcome() {
        let target = tempfile::tempdir().unwrap();
        write_scan_stage(target.path(), "complete-scan", PhaseStageOutcome::Completed);
        write_scan_stage(target.path(), "partial-scan", PhaseStageOutcome::Partial);
        write_scan_stage(target.path(), "failed-scan", PhaseStageOutcome::Failed);

        let partial_refs = ["complete-scan", "partial-scan"]
            .map(str::to_string)
            .to_vec();
        assert_eq!(
            durable_phase_attempt_outcome(
                target.path(),
                WorkflowPhase::Scan,
                &partial_refs,
                "completed",
            ),
            PhaseAttemptOutcome::Partial
        );
        let refs = ["complete-scan", "partial-scan", "failed-scan"]
            .map(str::to_string)
            .to_vec();
        assert_eq!(
            durable_phase_attempt_outcome(target.path(), WorkflowPhase::Scan, &refs, "completed"),
            PhaseAttemptOutcome::Failed
        );
    }

    #[test]
    fn evidence_empty_map_is_partial_and_offers_only_recovery_actions() {
        let target = tempfile::tempdir().unwrap();
        write_empty_map_artifacts(target.path());
        let refs = vec!["threat-model-empty".to_string()];

        let outcome =
            durable_phase_attempt_outcome(target.path(), WorkflowPhase::Map, &refs, "completed");
        let blocker = map_evidence_blocker(target.path(), WorkflowPhase::Map, &refs, outcome);
        let mut session = ActivitySession::for_phase("threat-model-empty", WorkflowPhase::Map);
        session.mark_run_focus_terminal_pending("completed");
        let mut receipt = session.run_focus_receipt.take().unwrap();
        apply_map_evidence_blocker(&mut receipt, blocker.clone());

        assert_eq!(outcome, PhaseAttemptOutcome::Partial);
        assert!(blocker
            .as_deref()
            .is_some_and(|message| message.contains(&target.path().display().to_string())));
        assert_eq!(
            receipt.actions,
            vec![
                PhaseResultAction::Open,
                PhaseResultAction::RunAgain,
                PhaseResultAction::Discard,
            ]
        );
        assert_eq!(receipt.recommended_next, blocker);
    }

    #[test]
    fn indexed_source_keeps_map_completion_eligible() {
        let target = tempfile::tempdir().unwrap();
        let record = kuzushi_core::run_artifacts::ToolRunRecord::new(
            target.path(),
            "context-run",
            "tool",
            "context:build",
        );
        kuzushi_core::run_artifacts::record_tool_run_started(record, &serde_json::json!({}));
        kuzushi_core::run_artifacts::record_tool_run_complete(
            record,
            &serde_json::json!({
                "ok": true,
                "data": {"snapshot": {"filesIndexed": 1}}
            }),
        );

        assert_eq!(
            durable_phase_attempt_outcome(
                target.path(),
                WorkflowPhase::Map,
                &["context-run".to_string()],
                "partial",
            ),
            PhaseAttemptOutcome::Completed
        );
    }

    fn write_empty_map_artifacts(target: &std::path::Path) {
        let context = kuzushi_core::context_snapshot_path(target);
        let entries =
            kuzushi_core::workspace::workspace_state_root(target).join("entry-points.json");
        let threat_model = kuzushi_core::capabilities::persistent_threat_model_path(target);
        std::fs::create_dir_all(context.parent().unwrap()).unwrap();
        std::fs::write(context, serde_json::json!({"filesIndexed": 0}).to_string()).unwrap();
        std::fs::write(entries, serde_json::json!({"total": 0}).to_string()).unwrap();
        std::fs::write(
            threat_model,
            serde_json::json!({
                "dfd": {
                    "nodes": [{
                        "id": "n1",
                        "name": "empty repository scope",
                        "trustZone": "analysis-scope",
                        "type": "process"
                    }],
                    "flows": []
                },
                "threats": []
            })
            .to_string(),
        )
        .unwrap();
    }

    fn completed_live_session(run_id: &str) -> ActivitySession {
        use kuzushi_core::run_lifecycle::CommittedRange;
        let item = completed_terminal_item(run_id);
        let mut session = ActivitySession::new(run_id);
        session.observe_committed_range(CommittedRange {
            first_seq: 1,
            through_seq: 1,
        });
        session.apply_run_item(item).unwrap();
        session
    }

    fn write_terminal_run(
        target: &std::path::Path,
        run_id: &str,
        status: kuzushi_core::run_lifecycle::RunItemStatus,
    ) {
        use kuzushi_core::run_lifecycle::{
            RunItemId, RunItemRecord, RunItemSource, RunItemV1, RunItemWriter, SafeText,
            WorkflowContinuation,
        };

        let writer = RunItemWriter::open(target, run_id, None).unwrap();
        writer
            .emit_and_flush(RunItemRecord::new(
                RunItemId::new(),
                RunItemSource::Workflow,
                RunItemV1::TerminalOutcome {
                    status,
                    summary: SafeText::operator_visible(status.label()),
                    cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
                    continuation: WorkflowContinuation::NoFurtherAction {
                        reason: SafeText::operator_visible("phase stopped"),
                    },
                },
            ))
            .unwrap();
        writer.shutdown().unwrap();
    }

    fn completed_terminal_item(run_id: &str) -> kuzushi_core::run_lifecycle::RunItemEnvelopeV1 {
        use kuzushi_core::run_lifecycle::{
            RunId, RunItemEnvelopeV1, RunItemId, RunItemSource, RunItemStatus, RunItemV1, SafeText,
            WorkflowContinuation,
        };
        RunItemEnvelopeV1::new(
            1,
            RunId::parse(run_id).unwrap(),
            RunItemId::new(),
            RunItemSource::Workflow,
            RunItemV1::TerminalOutcome {
                status: RunItemStatus::Completed,
                summary: SafeText::operator_visible("completed"),
                cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
                continuation: WorkflowContinuation::NoFurtherAction {
                    reason: SafeText::operator_visible("done"),
                },
            },
            None,
        )
        .unwrap()
    }

    fn completed_attempt(run_id: &str) -> kuzushi_core::workflow_attempts::PhaseAttemptCompleted {
        kuzushi_core::workflow_attempts::PhaseAttemptCompleted::new(
            WorkflowPhase::Scan,
            vec![run_id.to_string()],
            PhaseTargetSnapshot {
                target: "/tmp/target".to_string(),
                revision: None,
                dirty: false,
            },
            PhaseAttemptOutcome::Completed,
        )
    }

    fn write_scan_stage(target: &std::path::Path, run_id: &str, outcome: PhaseStageOutcome) {
        let receipt = PhaseStageReceipt {
            phase: WorkflowPhase::Scan,
            outcome,
            run_refs: vec![run_id.to_string()],
            scan: Some(ScanStageData {
                scope: ScanStageScope {
                    inspected_files: None,
                    target: target.display().to_string(),
                    paths: Vec::new(),
                },
                plan: ScanStagePlan {
                    selection: "auto".to_string(),
                    engines: vec!["semgrep".to_string()],
                },
                engines: Vec::new(),
                finding_delta: ScanFindingDelta::default(),
                severity_counts: Vec::new(),
                artifact_delta: Vec::new(),
                duration_ms: 1,
                cost: None,
                target_snapshot: PhaseTargetSnapshot::capture(target),
            }),
        };
        let path =
            kuzushi_core::run_artifacts::run_dir(target, run_id).join(SAST_PHASE_STAGES_JSONL_FILE);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            format!("{}\n", serde_json::to_string(&receipt).unwrap()),
        )
        .unwrap();
    }

    fn phase_attempt_app(target: &std::path::Path) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target.to_path_buf()));
        app.engagement.set_phase(WorkflowPhase::Scan);
        app
    }

    #[test]
    fn credential_question_routes_to_setup_auth_without_opening_a_question_card() {
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-5.5".to_string());
        let mut app = ShellApp::new(config, None);
        app.set_activity(Some(ActivitySession::new("credential-run")));
        app.set_shell_view(ShellView::Activity);

        let effects = app.apply_current_job_event(ShellEvent::CredentialQuestionRouted {
            request_id: "credential-request".to_string(),
            run_id: "credential-run".to_string(),
        });

        assert_eq!(app.shell_view(), ShellView::Setup);
        assert_eq!(app.router.setup().editor(), Some(SetupEditor::Credentials));
        assert_eq!(app.router.auth_picker().provider(), "openai");
        assert!(app
            .activity()
            .is_some_and(|session| session.operator_question.is_none()));
        assert!(effects
            .iter()
            .any(|effect| matches!(effect, ShellEffect::ShowAuthStatus(_))));
    }

    fn assert_no_scan_attempt(target: &std::path::Path) {
        let ledger = kuzushi_core::workflow_attempts::load_phase_attempt_ledger(target).unwrap();
        let snapshot = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target);
        assert!(ledger
            .unresolved_for(WorkflowPhase::Scan, &snapshot)
            .is_none());
        assert!(ledger
            .selected_for(WorkflowPhase::Scan, &snapshot)
            .is_none());
    }

    fn continuation_actions(
        completed: &kuzushi_core::workflow_attempts::PhaseAttemptCompleted,
    ) -> Vec<PhaseResultAction> {
        completed
            .receipt
            .as_ref()
            .into_iter()
            .flat_map(|receipt| receipt.actions.iter())
            .filter(|action| {
                matches!(
                    action,
                    PhaseResultAction::SelectAndContinue | PhaseResultAction::SelectAndReport
                )
            })
            .copied()
            .collect()
    }

    fn assert_live_attempt_receipt(
        app: &ShellApp,
        attempt: &kuzushi_core::workflow_attempts::PhaseAttemptRecord,
    ) {
        let receipt = app
            .activity()
            .and_then(|session| session.run_focus_receipt.as_ref())
            .expect("published Run Focus receipt");
        assert_eq!(receipt.run_count, 2);
        assert_eq!(
            receipt.attempt_id.as_deref(),
            Some(attempt.completed.attempt_id.as_str())
        );
    }

    fn agent_advisory_app(target: &std::path::Path, run_id: &str) -> ShellApp {
        record_agent_run_started(
            Some(target),
            run_id,
            &serde_json::json!({"question": "what next?"}),
            "openai:gpt-test".to_string(),
            None,
            Vec::new(),
        )
        .unwrap();
        let mut app = phase_attempt_app(target);
        app.set_activity(Some(ActivitySession::for_phase(
            run_id,
            WorkflowPhase::Scan,
        )));
        app.set_agent_chat(Some(AgentChatView {
            question: "what next?".to_string(),
            running: true,
            run_id: Some(run_id.to_string()),
            ..AgentChatView::default()
        }));
        app.set_agent_artifact_target(Some(target.to_path_buf()));
        app
    }

    fn effectful_semgrep_after_plan_app(target: &std::path::Path, run_id: &str) -> ShellApp {
        initialize_clean_git_fixture(target);
        let target = target.canonicalize().expect("canonical fixture target");
        kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
            kuzushi_core::run_artifacts::ToolRunRecord::new(
                &target,
                run_id,
                "tool",
                "semgrep:scan",
            ),
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let mut app = phase_attempt_app(&target);
        let prior = ActivitySession::for_phase("plan-advisory", WorkflowPhase::Scan);
        let mut activity = ActivitySession::for_phase(run_id, WorkflowPhase::Scan)
            .with_phase_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new());
        activity.continue_run_focus_sequence_from(&prior);
        app.set_activity(Some(activity));
        app.start_tool_run(
            "semgrep:scan".to_string(),
            ScanCancellation::default(),
            run_id.to_string(),
            target,
            None,
        );
        app
    }

    fn initialize_clean_git_fixture(target: &std::path::Path) {
        run_fixture_git(target, &["init"]);
        run_fixture_git(target, &["config", "user.email", "kuzushi@example.test"]);
        run_fixture_git(target, &["config", "user.name", "Kuzushi Test"]);
        std::fs::write(target.join("fixture.rs"), "fn fixture() {}\n").unwrap();
        run_fixture_git(target, &["add", "fixture.rs"]);
        run_fixture_git(
            target,
            &["-c", "commit.gpgsign=false", "commit", "-m", "fixture"],
        );
    }

    fn run_fixture_git(target: &std::path::Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(target)
            .args(args)
            .output()
            .expect("git available for fixture");
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn finish_effectful_semgrep(app: &mut ShellApp) {
        let effects = app.apply_job_event(ShellEvent::Tool(ToolEvent::Finished {
            tool_name: "semgrep:scan".to_string(),
            result: serde_json::json!({
                "ok": true,
                "status": "completed",
                "output": "no findings",
                "data": {"count": 0}
            }),
        }));
        EffectRuntime::execute(app, effects);
        assert!(app.finalize_run_focus_if_idle());
    }

    #[test]
    fn nested_scan_run_references_are_deduplicated_from_structured_results() {
        let value = serde_json::json!({
            "parent": "scan-parent",
            "native": ["semgrep-1", "secrets-1", "semgrep-1"],
            "agentic": null,
            "nested": { "taint": "taint-1" }
        });
        let mut refs = Vec::new();
        collect_result_run_refs(&value, &mut refs);
        assert_eq!(refs.len(), 4);
        assert_eq!(
            refs.into_iter().collect::<std::collections::BTreeSet<_>>(),
            ["scan-parent", "secrets-1", "semgrep-1", "taint-1"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
    }

    #[test]
    fn phase_intent_planner_proposal_is_not_a_scan_attempt() {
        let target = tempfile::tempdir().unwrap();
        let mut app = phase_attempt_app(target.path());
        app.set_activity(Some(ActivitySession::for_phase(
            "plan-advisory",
            WorkflowPhase::Scan,
        )));
        app.set_planner_running(true);

        let effects = app.apply_job_event(ShellEvent::Plan(PlanEvent::Proposed {
            plan: PlanProposal {
                goal: "scan the target".to_string(),
                summary: "run semgrep after approval".to_string(),
                changes: vec![PlanChange::RunTool {
                    phase: WorkflowPhase::Scan,
                    tool: "semgrep:scan".to_string(),
                    input: None,
                }],
                unsupported: Vec::new(),
            },
            audit: AgentCallAudit::test(),
        }));
        EffectRuntime::execute(&mut app, effects);

        assert!(app.finalize_run_focus_if_idle());
        assert_eq!(
            app.activity()
                .and_then(|session| session.run_focus_receipt.as_ref())
                .and_then(|receipt| receipt.attempt_id.as_deref()),
            None
        );
        assert_no_scan_attempt(target.path());
    }

    #[test]
    fn threat_advice_is_not_a_scan_attempt() {
        let threat_target = tempfile::tempdir().unwrap();
        let mut threat_app = phase_attempt_app(threat_target.path());
        threat_app.set_activity(Some(ActivitySession::for_phase(
            "threat-advisory",
            WorkflowPhase::Scan,
        )));
        threat_app.set_threat_worker_running(true);
        let effects = threat_app.apply_job_event(ShellEvent::Threat(ThreatPatchEvent::Answer {
            text: "review the trust boundary".to_string(),
            audit: AgentCallAudit::test(),
        }));
        EffectRuntime::execute(&mut threat_app, effects);
        assert!(threat_app.finalize_run_focus_if_idle());
        assert_no_scan_attempt(threat_target.path());
    }

    #[test]
    fn agent_advice_with_replay_artifacts_is_not_a_scan_attempt() {
        let agent_target = tempfile::tempdir().unwrap();
        let run_id = "agent-advisory";
        let mut agent_app = agent_advisory_app(agent_target.path(), run_id);
        let effects = agent_app.apply_job_event(ShellEvent::Agent(AgentEvent::Answered {
            text: "inspect the parser".to_string(),
            audit: AgentCallAudit::test(),
        }));
        EffectRuntime::execute(&mut agent_app, effects);

        assert_eq!(
            kuzushi_core::load_run_summary(agent_target.path(), run_id)
                .unwrap()
                .kind,
            "shell"
        );
        assert!(agent_app.finalize_run_focus_if_idle());
        assert_no_scan_attempt(agent_target.path());
    }

    #[test]
    fn persisted_descriptor_tool_completion_creates_a_scan_attempt() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "effectful-semgrep";
        let mut app = effectful_semgrep_after_plan_app(target.path(), run_id);
        finish_effectful_semgrep(&mut app);
        assert_live_and_replayed_phase_receipt_match(&app, target.path(), run_id);

        let ledger =
            kuzushi_core::workflow_attempts::load_phase_attempt_ledger(target.path()).unwrap();
        let snapshot = kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target.path());
        let attempt = ledger
            .unresolved_for(WorkflowPhase::Scan, &snapshot)
            .expect("descriptor tool completion must create a selectable result");
        assert_eq!(attempt.completed.run_refs, vec![run_id.to_string()]);
        assert_live_attempt_receipt(&app, attempt);
        assert_eq!(
            continuation_actions(&attempt.completed),
            vec![PhaseResultAction::SelectAndContinue],
            "without a typed finding-delta observation, Scan must continue to Review"
        );
        assert!(ledger
            .selected_for(WorkflowPhase::Scan, &snapshot)
            .is_none());
    }

    #[test]
    fn durable_phase_receipt_is_delivered_to_live_projection() {
        let target = tempfile::tempdir().unwrap();
        let run_id = "live-phase-receipt";
        let mut app = effectful_semgrep_after_plan_app(target.path(), run_id);

        finish_effectful_semgrep(&mut app);

        assert_live_and_replayed_phase_receipt_match(&app, target.path(), run_id);
    }

    fn assert_live_and_replayed_phase_receipt_match(
        app: &ShellApp,
        target: &std::path::Path,
        run_id: &str,
    ) {
        let replay = kuzushi_core::run_lifecycle::load_run_projection(target, run_id)
            .unwrap()
            .projection
            .phase_receipt
            .unwrap_or_else(|| panic!("replayed typed phase receipt; logs={:?}", app.log_lines()));
        let live = app
            .activity()
            .and_then(|session| session.run_projection.phase_receipt.as_ref())
            .unwrap_or_else(|| panic!("live typed phase receipt; logs={:?}", app.log_lines()));
        assert_eq!(live, &replay);
    }

    #[test]
    fn settled_foreground_run_restores_exact_origin_with_receipt() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut session = ActivitySession::new("run-done").with_run_focus_origin(RunFocusOrigin {
            view: ShellView::Home,
            input_mode: InputMode::Navigate,
            auto_return: true,
        });
        session.mark_run_focus_terminal_pending("completed");
        app.set_activity(Some(session));
        app.set_shell_view(ShellView::Activity);
        app.set_input_mode(InputMode::Navigate);

        assert!(app.finalize_run_focus_if_idle());

        assert_eq!(app.shell_view(), ShellView::Home);
        assert_eq!(app.input_mode(), InputMode::Navigate);
        assert!(app.activity().is_some_and(|session| {
            session
                .run_focus_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.outcome == "completed" && receipt.run_count == 1)
        }));
    }

    #[test]
    fn finalization_refreshes_receipt_from_settled_cost() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut session = ActivitySession::new("run-cost");
        session.settle_runtime_cost(kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE);
        session.mark_run_focus_terminal_pending("completed");
        assert_eq!(
            session
                .run_focus_receipt
                .as_ref()
                .map(|receipt| receipt.cost.as_str()),
            Some("cost not recorded")
        );
        session.settle_runtime_cost(kuzushi_core::runtime::RuntimeCostReport::known(
            kuzushi_core::runtime::RuntimeCost::ZERO,
        ));
        app.set_activity(Some(session));

        assert!(app.finalize_run_focus_if_idle());
        assert_eq!(
            app.activity()
                .and_then(|session| session.run_focus_receipt.as_ref())
                .map(|receipt| receipt.cost.as_str()),
            Some("$0.0000")
        );
    }

    #[test]
    fn manual_or_background_session_never_hijacks_the_current_view() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut session = ActivitySession::new("run-done");
        session.mark_run_focus_terminal_pending("failed");
        session.run_focus_backgrounded = true;
        app.set_activity(Some(session));
        app.set_shell_view(ShellView::Home);

        assert!(app.finalize_run_focus_if_idle());
        assert_eq!(app.shell_view(), ShellView::Home);
    }

    #[test]
    fn canceled_task_wins_over_a_generic_completed_activity_label() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut session = ActivitySession::new("run-canceled");
        let mut task = DagTaskRow::queued("triage:run".into(), "triage".into(), Vec::new());
        task.state = DagTaskState::Canceled;
        session.tasks.insert(task.task_id.clone(), task);
        app.set_activity(Some(session));
        app.set_completed_activity("triage:run", "canceled");

        app.mark_run_focus_terminal_pending("completed");

        assert_eq!(
            app.activity()
                .and_then(|session| session.run_focus_receipt.as_ref())
                .map(|receipt| receipt.outcome.as_str()),
            Some("canceled")
        );
    }

    #[test]
    fn fast_final_plan_step_restores_setup_after_phase_reality_advances() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Setup);
        app.set_input_mode(InputMode::Navigate);
        app.engagement.set_phase(WorkflowPhase::Map);

        let session = app.capture_run_focus_origin(ActivitySession::new("map-fast"));
        app.set_activity(Some(session));
        app.set_shell_view(ShellView::Activity);
        app.set_running_tool_for_test("secrets:scan");
        app.engagement.set_running_tool("secrets:scan".to_string());

        let effects = app.apply_job_event(ShellEvent::Tool(ToolEvent::Finished {
            tool_name: "secrets:scan".to_string(),
            result: serde_json::json!({ "output": "no secrets found" }),
        }));

        assert_eq!(app.shell_view(), ShellView::Activity);
        assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Scan));
        assert!(app.activity().is_some_and(|session| {
            session.run_focus_terminal_pending
                && session
                    .run_focus_origin
                    .is_some_and(|origin| origin.view == ShellView::Setup)
        }));
        assert!(effects
            .iter()
            .any(|effect| { matches!(effect, ShellEffect::RecordToolRun(_)) }));

        assert!(app.finalize_run_focus_if_idle());
        assert_eq!(app.shell_view(), ShellView::Setup);
        assert_eq!(app.input_mode(), InputMode::Navigate);
        assert_eq!(app.engagement.current_phase(), Some(WorkflowPhase::Scan));
        assert!(app.activity().is_some_and(|session| {
            session
                .run_focus_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.outcome == "completed" && receipt.run_count == 1)
        }));
    }

    #[test]
    fn final_fix_step_defers_workbench_navigation_until_origin_restores() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Home);
        app.engagement.set_phase(WorkflowPhase::Fix);

        let session = app.capture_run_focus_origin(ActivitySession::new("fix-fast"));
        app.set_activity(Some(session));
        app.set_shell_view(ShellView::Activity);
        app.set_running_tool_for_test("patch:synthesize");
        app.engagement
            .set_running_tool("patch:synthesize".to_string());

        app.apply_job_event(ShellEvent::Tool(ToolEvent::Finished {
            tool_name: "patch:synthesize".to_string(),
            result: serde_json::json!({ "output": "patch ready" }),
        }));

        assert_eq!(app.shell_view(), ShellView::Activity);
        assert_eq!(app.engagement.current_phase(), None);
        assert!(app.finalize_run_focus_if_idle());
        assert_eq!(app.shell_view(), ShellView::Home);
    }
}
