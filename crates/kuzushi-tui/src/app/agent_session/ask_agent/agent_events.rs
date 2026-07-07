use super::*;

impl ShellApp {
    pub(crate) fn apply_agent_event(&mut self, event: AgentEvent) -> Vec<ShellEffect> {
        let state = AgentEventState::from_chat(self.agent_chat());
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
        self.record_agent_cost(audit.cost_usd);
        if state.abort_requested {
            self.log(
                "agent",
                "LangGraph response arrived after abort request; ignored",
            );
            self.set_refused_activity("agent", "response ignored after abort request");
            return Vec::new();
        }
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
        self.record_agent_cost(audit.cost_usd);
        if state.abort_requested {
            self.log(
                "agent",
                format!("LangGraph ended after abort request: {error}"),
            );
            self.set_refused_activity("agent", "worker ended after abort request");
            return Vec::new();
        }
        self.set_error_notice("ask", error.clone());
        self.set_refused_activity("agent", "model request failed");
        self.agent_failure_record(error, audit, state)
    }

    fn record_agent_cost(&mut self, cost_usd: Option<f64>) {
        if let Some(cost_usd) = cost_usd {
            self.record_cost(cost_usd);
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
            target: self.target_owned(),
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
            target: self.target_owned(),
            run_id,
            latency_ms: state.latency_ms,
            audit,
            outcome: AgentRunOutcome::Failed { error },
        })]
    }

    pub(crate) fn record_agent_run_effect(&self, record: AgentRunRecord) {
        match &record.outcome {
            AgentRunOutcome::Complete { answer_chars } => {
                record_agent_trace_success(&record, *answer_chars);
            }
            AgentRunOutcome::Failed { error } => {
                record_agent_trace_failure(&record, error);
            }
        }
    }
}

fn record_agent_trace_success(record: &AgentRunRecord, answer_chars: usize) {
    append_llm_trace_step(
        record.target.as_deref(),
        &record.run_id,
        "llm",
        &format!("answer ({answer_chars} chars)"),
        record.latency_ms,
        &record.audit,
    );
    write_agent_run_summary(record.target.as_deref(), &record.run_id, "complete");
    append_run_status_event(
        record.target.as_deref(),
        &record.run_id,
        "agent:ask",
        "completed",
        "agent:ask completed",
    );
}

fn record_agent_trace_failure(record: &AgentRunRecord, error: &str) {
    append_llm_trace_step(
        record.target.as_deref(),
        &record.run_id,
        "refused",
        &short_label(error, 80),
        record.latency_ms,
        &record.audit,
    );
    write_agent_run_summary(record.target.as_deref(), &record.run_id, "failed");
    append_run_status_event(
        record.target.as_deref(),
        &record.run_id,
        "agent:ask",
        "failed",
        "agent:ask failed",
    );
    write_run_failure_handoff(
        record.target.as_deref(),
        &record.run_id,
        "agent:ask",
        "failed",
        error,
    );
}

fn write_agent_run_summary(target: Option<&std::path::Path>, run_id: &str, status: &str) {
    write_run_summary(
        target,
        run_id,
        status,
        None,
        target
            .map(|p| p.display().to_string())
            .as_deref()
            .unwrap_or("."),
    );
}

struct AgentEventState {
    abort_requested: bool,
    run_id: Option<String>,
    latency_ms: Option<u64>,
}

impl AgentEventState {
    fn from_chat(agent: Option<&AgentChatView>) -> Self {
        let started_secs = agent.map(|agent| agent.started_secs).unwrap_or(0);
        Self {
            abort_requested: agent.is_some_and(|agent| agent.abort_requested),
            run_id: agent.and_then(|agent| agent.run_id.clone()),
            latency_ms: agent_latency_ms(started_secs),
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
