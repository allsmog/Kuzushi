use super::*;
use std::time::{Duration, Instant};

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
            | self.apply_view_hydration_results()
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
        let dropped = self.jobs().take_dropped_live_trace_count();
        outcome.changed |= self.degrade_dropped_live_trace_cost(dropped);
        outcome
    }

    pub(crate) fn apply_job_event(&mut self, event: ShellEvent) -> Vec<ShellEffect> {
        let kind = event.kind();
        let finishes_slot = self.job_event_finishes_slot(&event);
        let terminal_fallback = finishes_slot.then(|| run_focus_event_outcome(&event));
        if finishes_slot {
            self.jobs_mut().finish(kind);
        }
        let mut effects = self.apply_current_job_event(event);
        if finishes_slot {
            self.mark_run_focus_terminal_pending(
                terminal_fallback.as_deref().unwrap_or("completed"),
            );
            self.clear_finished_job(kind);
            // Centralized steer-queue drain: every terminal job event (scan
            // success/failure, tool success/failure, agent/plan/threat finish)
            // flows through here, so the operator steer queue drains on ALL
            // completion paths — not just a successful background-tool finish.
            effects.extend(self.advance_steer_queue());
        }
        effects
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
        self.restore_run_focus_origin(&completion);
        self.publish_run_focus_receipt(
            completion.receipt,
            completion.answer_acknowledgement.as_deref(),
        );
        true
    }

    fn pending_run_focus_completion(&self) -> Option<RunFocusCompletion> {
        let session = self.activity()?;
        session
            .run_focus_terminal_pending
            .then(|| RunFocusCompletion {
                origin: session.run_focus_origin,
                backgrounded: session.run_focus_backgrounded,
                receipt: session.run_focus_receipt.clone(),
                answer_acknowledgement: session.operator_answer_acknowledgement.clone(),
                pending_viz: session.run_focus_pending_viz,
            })
    }

    fn clear_pending_run_focus_completion(&mut self) {
        if let Some(session) = self.activity_mut() {
            session.run_focus_terminal_pending = false;
            session.run_focus_pending_viz = None;
        }
    }

    fn restore_run_focus_origin(&mut self, completion: &RunFocusCompletion) {
        if !completion.should_restore(self.shell_view()) {
            return;
        }
        let origin = completion.origin.expect("restore decision requires origin");
        self.set_shell_view(origin.view);
        self.set_input_mode(origin.input_mode);
        if let Some(page) = completion.pending_viz {
            self.open_scene_to_page(page);
        }
    }

    fn publish_run_focus_receipt(
        &mut self,
        receipt: Option<RunFocusReceipt>,
        answer_acknowledgement: Option<&str>,
    ) {
        let Some(mut receipt) = receipt else {
            return;
        };
        self.enrich_run_focus_receipt(&mut receipt);
        let map_blocker = self.reconcile_durable_phase_outcome(&mut receipt);
        self.tailor_phase_result_destination(&mut receipt);
        apply_map_evidence_blocker(&mut receipt, map_blocker);
        self.persist_phase_attempt(&mut receipt);
        if let Some(session) = self.activity_mut() {
            session.run_focus_receipt = Some(receipt.clone());
        }
        self.set_info_notice("run", run_receipt_notice(&receipt, answer_acknowledgement));
    }

    fn enrich_run_focus_receipt(&self, receipt: &mut RunFocusReceipt) {
        let Some(target) = self.target() else {
            return;
        };
        let nested = nested_run_refs(target, &receipt.run_refs);
        extend_unique_run_refs(&mut receipt.run_refs, nested);
        let (findings, artifacts) = receipt_run_changes(target, &receipt.run_refs);
        receipt.changed_findings = findings;
        receipt.changed_artifacts = artifacts.into_iter().collect();
    }

    fn reconcile_durable_phase_outcome(&self, receipt: &mut RunFocusReceipt) -> Option<String> {
        let target = self.target()?;
        let phase = receipt.origin_phase?;
        let run_refs = self.canonical_descriptor_run_refs(target, phase, &receipt.run_refs);
        if run_refs.is_empty() {
            return None;
        }
        let outcome = durable_phase_attempt_outcome(target, phase, &run_refs, &receipt.outcome);
        receipt.outcome = phase_attempt_outcome_label(outcome).to_string();
        map_evidence_blocker(target, phase, &run_refs, outcome)
    }

    /// Keep the single `n` action truthful for the result that just landed.
    /// The operator still selects the attempt before reality is re-derived;
    /// this only decides whether the card names the next phase or Report.
    fn tailor_phase_result_destination(&self, receipt: &mut RunFocusReceipt) {
        let Some(phase) = receipt.origin_phase else {
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

    fn persist_phase_attempt(&mut self, receipt: &mut RunFocusReceipt) {
        use kuzushi_core::workflow_attempts::append_phase_attempt_completed;

        let Some((target, completed)) = self.effectful_phase_attempt(receipt) else {
            return;
        };
        let phase = completed.phase;
        let attempt_id = completed.attempt_id.clone();
        match append_phase_attempt_completed(&target, completed) {
            Ok(_) => {
                receipt.attempt_id = Some(attempt_id);
                self.engagement.clear_attempt_lineage(phase);
                self.refresh_phase_attempt_projection();
            }
            Err(error) => self.log(
                "workflow",
                format!(
                    "run completed, but its phase attempt receipt could not be recorded: {error}"
                ),
            ),
        }
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
        let mut completed = PhaseAttemptCompleted::new(
            phase,
            run_refs.clone(),
            PhaseTargetSnapshot::capture(&target),
            durable_phase_attempt_outcome(&target, phase, &run_refs, &receipt.outcome),
        )
        .with_receipt(receipt.durable_metadata());
        if let Some(reason) = map_evidence_blocker(&target, phase, &run_refs, completed.outcome) {
            completed = completed.with_selection_blocked(reason);
        }
        if let Some((parent, derivation)) = self.engagement.attempt_lineage(phase) {
            completed = completed.derived_from(parent, derivation);
        }
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
        let classification = kuzushi_core::modules::autonomy::classify_descriptor(descriptor);
        (classification
            == Some(kuzushi_core::modules::autonomy::ToolClassification::Phase(
                phase,
            )))
        .then_some(summary.run_id)
    }

    fn run_focus_sequence_is_settled(&self) -> bool {
        !self.has_running_work()
            && !self.engagement.has_pending_chain()
            && !self.engagement.has_pending_prereq_prompt()
            && self.engagement.planning_queues_empty()
            && self.steer_queue().len() == 0
    }

    fn apply_current_job_event(&mut self, event: ShellEvent) -> Vec<ShellEffect> {
        match event {
            ShellEvent::Trace(step) => {
                self.apply_trace_step(step);
                Vec::new()
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

    fn job_event_finishes_slot(&self, event: &ShellEvent) -> bool {
        match event {
            ShellEvent::Trace(_)
            | ShellEvent::Scan(ScanEvent::Stage(_))
            | ShellEvent::OperatorQuestion(_)
            | ShellEvent::OperatorQuestionCompleted(_)
            | ShellEvent::CredentialQuestionRouted { .. } => false,
            ShellEvent::Scan(ScanEvent::Finished { .. } | ScanEvent::Failed { .. }) => {
                !self.tool_is_running() && self.scan().is_some_and(|scan| scan.running)
            }
            ShellEvent::Tool(
                ToolEvent::Finished { .. } | ToolEvent::Failed { .. } | ToolEvent::Refused { .. },
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

    fn apply_trace_step(&mut self, step: RunTraceStep) {
        let (run_id, cost, error) = {
            let session =
                self.activity_or_insert_with(|| ActivitySession::new(default_activity_run_id()));
            let cost = session.apply_step_with_cost(step);
            let error = session
                .runtime_cost_report()
                .err()
                .map(|error| error.to_string());
            (session.run_id.clone(), cost, error)
        };
        if let Some(error) = error {
            self.report_cost_accounting_error(error);
        } else if let Some(cost) = cost {
            self.observe_run_cost_report(&run_id, cost);
        }
    }

    fn degrade_dropped_live_trace_cost(&mut self, dropped: usize) -> bool {
        if dropped == 0 {
            return false;
        }
        let Some(run_id) = self.activity().map(|activity| activity.run_id.clone()) else {
            return false;
        };
        if !self.session().run_may_call_provider(&run_id) {
            return false;
        }
        self.mark_run_cost_incomplete(&run_id);
        self.log(
            "cost",
            format!("{dropped} live trace frame(s) dropped; run cost is incomplete until terminal reconciliation"),
        );
        true
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
        self.runtime_state.clear_cleared_agent_run();
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

fn run_receipt_notice(receipt: &RunFocusReceipt, answer_acknowledgement: Option<&str>) -> String {
    let summary = format!("run receipt · {}", receipt.summary());
    answer_acknowledgement.map_or(summary.clone(), |acknowledgement| {
        format!("{summary} · {acknowledgement}")
    })
}

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
    let fallback = phase_attempt_outcome_from_label(fallback);
    if matches!(
        fallback,
        kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Failed
            | kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Canceled
    ) {
        return fallback;
    }
    if phase == WorkflowPhase::Map {
        let facts = kuzushi_core::workflow_attempts::collect_map_evidence(target, run_refs);
        return if kuzushi_core::workflow_attempts::assess_map_evidence(&facts).is_adequate() {
            kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Completed
        } else {
            kuzushi_core::workflow_attempts::PhaseAttemptOutcome::Partial
        };
    }
    if phase != WorkflowPhase::Scan {
        return fallback;
    }
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
        | ShellEvent::Tool(ToolEvent::Finished { result, .. }) => {
            match kuzushi_core::tool_result_status(result) {
                kuzushi_core::ToolResultStatus::Completed => "completed",
                kuzushi_core::ToolResultStatus::Partial => "partial",
                kuzushi_core::ToolResultStatus::Skipped => "skipped",
                kuzushi_core::ToolResultStatus::Failed => "failed",
            }
        }
        ShellEvent::Tool(ToolEvent::Refused { .. }) => "refused",
        ShellEvent::Scan(ScanEvent::Failed { .. })
        | ShellEvent::Tool(ToolEvent::Failed { .. })
        | ShellEvent::Agent(AgentEvent::Failed { .. })
        | ShellEvent::Plan(PlanEvent::Failed { .. })
        | ShellEvent::Threat(ThreatPatchEvent::Failed { .. }) => "failed",
        ShellEvent::Agent(AgentEvent::Answered { .. })
        | ShellEvent::Plan(PlanEvent::Proposed { .. })
        | ShellEvent::Threat(ThreatPatchEvent::Proposed { .. } | ThreatPatchEvent::Answer { .. }) => {
            "completed"
        }
        ShellEvent::Trace(_)
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
        assert!(records.iter().all(|record| record
            .payload
            .get("prompt")
            .or_else(|| record.payload.get("answer"))
            .is_none_or(serde_json::Value::is_null)));
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
        let context = kuzushi_core::context_snapshot_path(target.path());
        std::fs::create_dir_all(context.parent().unwrap()).unwrap();
        std::fs::write(context, serde_json::json!({"filesIndexed": 1}).to_string()).unwrap();

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

    fn write_scan_stage(target: &std::path::Path, run_id: &str, outcome: PhaseStageOutcome) {
        let receipt = PhaseStageReceipt {
            phase: WorkflowPhase::Scan,
            outcome,
            run_refs: vec![run_id.to_string()],
            scan: Some(ScanStageData {
                scope: ScanStageScope {
                    target: target.display().to_string(),
                    paths: Vec::new(),
                },
                plan: ScanStagePlan {
                    selection: "auto".to_string(),
                    engines: vec!["semgrep".to_string()],
                },
                engines: Vec::new(),
                finding_delta: ScanFindingDelta::default(),
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
        kuzushi_core::run_artifacts::try_record_tool_run_started_with_reproducibility(
            kuzushi_core::run_artifacts::ToolRunRecord::new(target, run_id, "tool", "semgrep:scan"),
            &serde_json::json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let mut app = phase_attempt_app(target);
        let prior = ActivitySession::for_phase("plan-advisory", WorkflowPhase::Scan);
        let mut activity = ActivitySession::for_phase(run_id, WorkflowPhase::Scan);
        activity.continue_run_focus_sequence_from(&prior);
        app.set_activity(Some(activity));
        app.start_tool_run(
            "semgrep:scan".to_string(),
            ScanCancellation::default(),
            run_id.to_string(),
            target.to_path_buf(),
            None,
        );
        app
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
        let effects = app.apply_job_event(ShellEvent::Tool(ToolEvent::Finished {
            tool_name: "semgrep:scan".to_string(),
            result: serde_json::json!({
                "ok": true,
                "status": "completed",
                "output": "no findings",
                "data": {"count": 0}
            }),
        }));
        EffectRuntime::execute(&mut app, effects);
        assert!(app.finalize_run_focus_if_idle());

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
            vec![PhaseResultAction::SelectAndReport],
            "a clean Scan receipt must offer one unambiguous Use & Report action"
        );
        assert!(ledger
            .selected_for(WorkflowPhase::Scan, &snapshot)
            .is_none());
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

fn default_activity_run_id() -> String {
    format!(
        "manual-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    )
}
