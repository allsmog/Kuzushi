use super::*;

impl ShellApp {
    pub(crate) fn apply_agent_event(&mut self, event: AgentEvent) -> Vec<ShellEffect> {
        if let AgentEvent::ResponseText(event) = event {
            self.apply_agent_response_text(event);
            return Vec::new();
        }
        if let Some(session) = self.activity_mut() {
            session.operator_question = None;
        }
        let state = AgentEventState::from_app(self);
        match event {
            AgentEvent::ResponseText(_) => Vec::new(),
            AgentEvent::Answered { text, audit } => self.apply_agent_answer(text, audit, state),
            AgentEvent::Failed { error, audit } => self.apply_agent_failure(error, audit, state),
        }
    }

    fn apply_agent_response_text(
        &mut self,
        event: kuzushi_openai::langgraph_runtime::ResponseTextEvent,
    ) {
        use kuzushi_openai::langgraph_runtime::ResponseTextEvent;
        let Some(agent) = self
            .agent_chat_mut()
            .filter(|chat| chat.running && !chat.abort_requested)
        else {
            return;
        };
        match event {
            ResponseTextEvent::Reset => agent.partial_answer.clear(),
            ResponseTextEvent::Delta(text) => agent.partial_answer.push_str(&text),
        }
        self.router.answers_mut().follow_response = true;
    }

    fn apply_agent_answer(
        &mut self,
        text: String,
        audit: AgentCallAudit,
        state: AgentEventState,
    ) -> Vec<ShellEffect> {
        self.settle_agent_answer_state(&text, state.abort_requested);
        self.record_agent_cost(&audit, state.run_id.as_deref());
        if state.abort_requested {
            return self.apply_aborted_agent_answer(audit, state);
        }
        self.apply_completed_agent_answer(text, audit, state)
    }

    fn settle_agent_answer_state(&mut self, text: &str, abort_requested: bool) {
        if let Some(agent) = self.agent_chat_mut() {
            agent.running = false;
            agent.abort_requested = false;
            if abort_requested {
                agent.answer = None;
                agent.error = Some("response arrived after abort request; ignored".to_string());
            } else {
                agent.answer = Some(text.to_string());
                agent.partial_answer.clear();
                agent.error = None;
            }
        }
    }

    fn apply_aborted_agent_answer(
        &mut self,
        audit: AgentCallAudit,
        state: AgentEventState,
    ) -> Vec<ShellEffect> {
        self.log(
            "agent",
            "LangGraph response arrived after abort request; ignored",
        );
        self.set_agent_terminal_activity(
            state.auxiliary_read_only,
            LiveActivityPhase::Refused,
            "response ignored after abort request",
        );
        self.agent_canceled_record(
            "response arrived after abort request".to_string(),
            audit,
            state,
        )
    }

    fn apply_completed_agent_answer(
        &mut self,
        text: String,
        audit: AgentCallAudit,
        state: AgentEventState,
    ) -> Vec<ShellEffect> {
        self.record_session_event(
            kuzushi_core::session_transcript::SessionEvent::AgentAssistantTurn {
                text: text.clone(),
            },
        );
        self.log("answer", text.clone());
        // Refresh the answer document in place; completion never changes focus.
        self.set_agent_terminal_activity(
            state.auxiliary_read_only,
            LiveActivityPhase::Completed,
            "answer received · workbench → answers",
        );
        self.agent_success_record(&text, audit, state)
    }

    fn apply_agent_failure(
        &mut self,
        error: String,
        audit: AgentCallAudit,
        state: AgentEventState,
    ) -> Vec<ShellEffect> {
        let safe_error = audit.failure_summary(&error);
        let message =
            crate::ui_view_models::model_failure_text(&audit, &error, state.run_id.as_deref());
        self.restore_failed_answer_draft(state.artifact_target.clone());
        self.settle_agent_failure_state(&message, state.abort_requested);
        self.record_agent_cost(&audit, state.run_id.as_deref());
        if state.abort_requested {
            return self.apply_aborted_agent_failure(error, audit, state);
        }
        self.set_error_notice("ask", message);
        self.set_agent_terminal_activity(
            state.auxiliary_read_only,
            LiveActivityPhase::Refused,
            &safe_error,
        );
        self.agent_failure_record(safe_error, audit, state)
    }

    fn settle_agent_failure_state(&mut self, message: &str, abort_requested: bool) {
        if let Some(agent) = self.agent_chat_mut() {
            agent.running = false;
            agent.abort_requested = false;
            agent.answer = None;
            agent.error = Some(agent_failure_message(message, abort_requested));
        }
    }

    fn apply_aborted_agent_failure(
        &mut self,
        error: String,
        audit: AgentCallAudit,
        state: AgentEventState,
    ) -> Vec<ShellEffect> {
        let safe_error = persisted_agent_cancellation(&error);
        self.log(
            "agent",
            format!("LangGraph ended after abort request: {safe_error}"),
        );
        self.set_agent_terminal_activity(
            state.auxiliary_read_only,
            LiveActivityPhase::Refused,
            "worker ended after abort request",
        );
        self.agent_canceled_record(safe_error, audit, state)
    }

    fn restore_failed_answer_draft(&mut self, target: Option<std::path::PathBuf>) {
        let Some(question) = self.agent_chat().map(|chat| chat.question.clone()) else {
            return;
        };
        let current_target = self.target_owned();
        self.router
            .answers_mut()
            .restore_failed_question(target, current_target, &question);
    }

    fn set_agent_terminal_activity(
        &mut self,
        auxiliary_read_only: bool,
        phase: LiveActivityPhase,
        detail: &str,
    ) {
        if auxiliary_read_only {
            return;
        }
        match phase {
            LiveActivityPhase::Completed => self.set_completed_activity("agent", detail),
            LiveActivityPhase::Refused => self.set_refused_activity_state("agent", detail),
            _ => {}
        }
    }

    fn record_agent_cost(&mut self, audit: &AgentCallAudit, run_id: Option<&str>) {
        let cost = audit.settlement_cost();
        if let Some(run_id) = run_id {
            self.begin_run_cost_tracking(run_id, true);
            self.settle_run_cost_report(run_id, cost);
        } else {
            self.record_cost_report(cost);
        }
    }

    fn agent_success_record(
        &self,
        text: &str,
        audit: AgentCallAudit,
        state: AgentEventState,
    ) -> Vec<ShellEffect> {
        let Some(run_id) = state.run_id else {
            return Vec::new();
        };
        vec![ShellEffect::RecordAgentRun(AgentRunRecord {
            target: state.artifact_target,
            run_id,
            latency_ms: state.latency_ms,
            audit,
            outcome: AgentRunOutcome::Complete {
                answer_chars: text.chars().count(),
            },
            auxiliary_read_only: state.auxiliary_read_only,
        })]
    }

    fn agent_failure_record(
        &self,
        error: String,
        audit: AgentCallAudit,
        state: AgentEventState,
    ) -> Vec<ShellEffect> {
        let Some(run_id) = state.run_id else {
            return Vec::new();
        };
        vec![ShellEffect::RecordAgentRun(AgentRunRecord {
            target: state.artifact_target,
            run_id,
            latency_ms: state.latency_ms,
            audit,
            outcome: AgentRunOutcome::Failed { error },
            auxiliary_read_only: state.auxiliary_read_only,
        })]
    }

    fn agent_canceled_record(
        &self,
        reason: String,
        audit: AgentCallAudit,
        state: AgentEventState,
    ) -> Vec<ShellEffect> {
        let Some(run_id) = state.run_id else {
            return Vec::new();
        };
        vec![ShellEffect::RecordAgentRun(AgentRunRecord {
            target: state.artifact_target,
            run_id,
            latency_ms: state.latency_ms,
            audit,
            outcome: AgentRunOutcome::Canceled { reason },
            auxiliary_read_only: state.auxiliary_read_only,
        })]
    }

    pub(crate) fn record_agent_run_effect(&mut self, record: AgentRunRecord) {
        self.persist_answer_conversation();
        let usable_result = matches!(record.outcome, AgentRunOutcome::Complete { .. });
        let persistence = match &record.outcome {
            AgentRunOutcome::Complete { answer_chars } => {
                record_agent_trace_success(&record, *answer_chars)
            }
            AgentRunOutcome::Failed { error } => record_agent_trace_failure(&record, error),
            AgentRunOutcome::Canceled { reason } => record_agent_trace_canceled(&record, reason),
        };
        if let Err(error) = persistence {
            self.report_agent_terminal_persistence_failure(&record, usable_result, error);
        }
        self.invalidate_view_hydration();
        self.workbench_cache()
            .borrow_mut()
            .invalidate_run_summaries();
    }

    fn report_agent_terminal_persistence_failure(
        &mut self,
        record: &AgentRunRecord,
        usable_result: bool,
        error: anyhow::Error,
    ) {
        let message = format!(
            "agent result retained, but run artifacts could not be finalized for {}: {error}",
            record.run_id
        );
        self.log("error", message.clone());
        self.set_error_notice("artifacts", message);
        if record.auxiliary_read_only {
            return;
        }
        if usable_result {
            self.set_partial_activity("agent", "answer retained; replay artifacts are incomplete");
        } else {
            self.set_failed_activity(
                "agent",
                "request failed and terminal artifacts are incomplete",
            );
        }
    }
}

fn record_agent_trace_success(record: &AgentRunRecord, answer_chars: usize) -> anyhow::Result<()> {
    record_agent_run_completed(
        record.target.as_deref(),
        &record.run_id,
        answer_chars,
        record.latency_ms,
        &record.audit,
    )
}

fn record_agent_trace_failure(record: &AgentRunRecord, error: &str) -> anyhow::Result<()> {
    let safe_error = record.audit.failure_summary(error);
    record_agent_run_failed(
        record.target.as_deref(),
        &record.run_id,
        &safe_error,
        &record.audit,
    )
}

fn record_agent_trace_canceled(record: &AgentRunRecord, reason: &str) -> anyhow::Result<()> {
    let safe_reason = persisted_agent_cancellation(reason);
    record_agent_run_canceled(
        record.target.as_deref(),
        &record.run_id,
        &safe_reason,
        &record.audit,
    )
}

fn persisted_agent_cancellation(reason: &str) -> String {
    format!(
        "model request canceled ({})",
        kuzushi_core::runtime::model_error_class_from_message(reason)
    )
}

struct AgentEventState {
    abort_requested: bool,
    run_id: Option<String>,
    latency_ms: Option<u64>,
    artifact_target: Option<std::path::PathBuf>,
    auxiliary_read_only: bool,
}

impl AgentEventState {
    fn from_app(app: &ShellApp) -> Self {
        let agent = app.agent_chat();
        let cleared = app.runtime_state.cleared_agent_run();
        let started_secs = agent
            .map(|agent| agent.started_secs)
            .or_else(|| cleared.map(|run| run.started_secs))
            .unwrap_or_default();
        Self {
            abort_requested: agent.is_some_and(|agent| agent.abort_requested)
                || cleared.is_some()
                || app
                    .agent_cancel_token()
                    .is_some_and(ScanCancellation::is_cancelled),
            run_id: agent
                .and_then(|agent| agent.run_id.clone())
                .or_else(|| cleared.and_then(|run| run.run_id.clone())),
            latency_ms: agent_latency_ms(started_secs),
            artifact_target: app
                .agent_artifact_target_owned()
                .or_else(|| cleared.and_then(|run| run.artifact_target.clone())),
            auxiliary_read_only: agent
                .map(|agent| agent.auxiliary_read_only)
                .or_else(|| cleared.map(|run| run.auxiliary_read_only))
                .unwrap_or(false),
        }
    }
}

fn agent_latency_ms(started_secs: u64) -> Option<u64> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (started_secs > 0 && now_secs >= started_secs).then_some((now_secs - started_secs) * 1000)
}

fn agent_failure_message(error: &str, abort_requested: bool) -> String {
    if abort_requested {
        "Ask canceled. Review the question before sending it again.".to_string()
    } else {
        error.to_string()
    }
}
