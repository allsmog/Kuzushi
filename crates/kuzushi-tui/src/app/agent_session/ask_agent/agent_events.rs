use super::*;

impl ShellApp {
    pub(crate) fn apply_agent_event(&mut self, event: AgentEvent) {
        let state = AgentEventState::from_chat(self.agent_chat.as_ref());
        match event {
            AgentEvent::Answered { text } => self.apply_agent_answer(text, state),
            AgentEvent::Failed { error } => self.apply_agent_failure(error, state),
        }
    }

    fn apply_agent_answer(&mut self, text: String, state: AgentEventState) {
        if let Some(agent) = &mut self.agent_chat {
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
        if state.abort_requested {
            self.log(
                "agent",
                "pi-agent-core response arrived after abort request; ignored",
            );
            return;
        }
        self.log("answer", text.clone());
        self.write_agent_trace_success(&text, &state);
    }

    fn apply_agent_failure(&mut self, error: String, state: AgentEventState) {
        if let Some(agent) = &mut self.agent_chat {
            agent.running = false;
            agent.abort_requested = false;
            agent.answer = None;
            agent.error = Some(agent_failure_message(&error, state.abort_requested));
        }
        if state.abort_requested {
            self.log(
                "agent",
                format!("pi-agent-core ended after abort request: {error}"),
            );
            return;
        }
        self.log("error", error.clone());
        self.write_agent_trace_failure(&error, &state);
    }

    fn write_agent_trace_success(&self, text: &str, state: &AgentEventState) {
        let Some(rid) = &state.run_id else {
            return;
        };
        append_trace_step(
            self.target.as_deref(),
            rid,
            2,
            "llm",
            &format!("answer ({} chars)", text.chars().count()),
            state.latency_ms,
            None,
        );
        self.write_agent_run_summary(rid, "complete");
    }

    fn write_agent_trace_failure(&self, error: &str, state: &AgentEventState) {
        let Some(rid) = &state.run_id else {
            return;
        };
        append_trace_step(
            self.target.as_deref(),
            rid,
            2,
            "refused",
            &short_label(error, 80),
            state.latency_ms,
            None,
        );
        self.write_agent_run_summary(rid, "failed");
    }

    fn write_agent_run_summary(&self, run_id: &str, status: &str) {
        write_run_summary(
            self.target.as_deref(),
            run_id,
            status,
            None,
            self.target
                .as_ref()
                .map(|p| p.display().to_string())
                .as_deref()
                .unwrap_or("."),
        );
    }
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
