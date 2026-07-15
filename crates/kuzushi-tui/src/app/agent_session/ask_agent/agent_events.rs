use super::*;

impl ShellApp {
    pub(crate) fn apply_agent_event(&mut self, event: AgentEvent) -> Vec<ShellEffect> {
        if let Some(session) = self.activity_mut() {
            session.operator_question = None;
        }
        let state = AgentEventState::from_app(self);
        match event {
            AgentEvent::Answered { text, audit } => self.apply_agent_answer(text, audit, state),
            AgentEvent::Failed { error, audit } => self.apply_agent_failure(error, audit, state),
        }
    }

    fn apply_agent_answer(
        &mut self,
        text: String,
        audit: AgentCallAudit,
        state: AgentEventState,
    ) -> Vec<ShellEffect> {
        if let Some(agent) = self.agent_chat_mut() {
            agent.running = false;
            agent.abort_requested = false;
            if state.abort_requested {
                agent.answer = None;
                agent.error = Some("response arrived after abort request; ignored".to_string());
            } else {
                agent.answer = Some(text.clone());
                agent.error = None;
            }
        }
        self.record_agent_cost(&audit, state.run_id.as_deref());
        if state.abort_requested {
            self.log(
                "agent",
                "LangGraph response arrived after abort request; ignored",
            );
            self.set_refused_activity("agent", "response ignored after abort request");
            return self.agent_canceled_record(
                "response arrived after abort request".to_string(),
                audit,
                state,
            );
        }
        self.record_session_event(
            kuzushi_core::session_transcript::SessionEvent::AgentAssistantTurn {
                text: text.clone(),
            },
        );
        self.log("answer", text.clone());
        self.set_completed_activity("agent", "answer received");
        self.agent_success_record(&text, audit, state)
    }

    fn apply_agent_failure(
        &mut self,
        error: String,
        audit: AgentCallAudit,
        state: AgentEventState,
    ) -> Vec<ShellEffect> {
        if let Some(agent) = self.agent_chat_mut() {
            agent.running = false;
            agent.abort_requested = false;
            agent.answer = None;
            agent.error = Some(agent_failure_message(&error, state.abort_requested));
        }
        self.record_agent_cost(&audit, state.run_id.as_deref());
        if state.abort_requested {
            self.log(
                "agent",
                format!("LangGraph ended after abort request: {error}"),
            );
            self.set_refused_activity("agent", "worker ended after abort request");
            return self.agent_canceled_record(
                format!("worker ended after abort request: {error}"),
                audit,
                state,
            );
        }
        self.set_error_notice("ask", error.clone());
        self.set_refused_activity("agent", "model request failed");
        self.agent_failure_record(error, audit, state)
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
        })]
    }

    pub(crate) fn record_agent_run_effect(&mut self, record: AgentRunRecord) {
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
    let trace = append_llm_trace_step(
        record.target.as_deref(),
        &record.run_id,
        "llm",
        &format!("answer ({answer_chars} chars)"),
        record.latency_ms,
        &record.audit,
    );
    let terminal = record_agent_run_completed(
        record.target.as_deref(),
        &record.run_id,
        answer_chars,
        record.latency_ms,
        &record.audit,
    );
    trace.and(terminal)
}

fn record_agent_trace_failure(record: &AgentRunRecord, error: &str) -> anyhow::Result<()> {
    let trace = append_llm_trace_step(
        record.target.as_deref(),
        &record.run_id,
        "refused",
        &short_label(error, 80),
        record.latency_ms,
        &record.audit,
    );
    let terminal = record_agent_run_failed(
        record.target.as_deref(),
        &record.run_id,
        error,
        &record.audit,
    );
    trace.and(terminal)
}

fn record_agent_trace_canceled(record: &AgentRunRecord, reason: &str) -> anyhow::Result<()> {
    let trace = append_llm_trace_step(
        record.target.as_deref(),
        &record.run_id,
        "refused",
        &short_label(reason, 80),
        record.latency_ms,
        &record.audit,
    );
    let terminal = record_agent_run_canceled(
        record.target.as_deref(),
        &record.run_id,
        reason,
        &record.audit,
    );
    trace.and(terminal)
}

struct AgentEventState {
    abort_requested: bool,
    run_id: Option<String>,
    latency_ms: Option<u64>,
    artifact_target: Option<std::path::PathBuf>,
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
        format!("request ended after abort request; last error: {error}")
    } else {
        error.to_string()
    }
}
