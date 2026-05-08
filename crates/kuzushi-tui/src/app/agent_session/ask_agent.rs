use super::prelude::*;
use super::*;

impl ShellApp {
    pub(crate) fn ask_agent(&mut self, question: &str) {
        let question = question.trim();
        if question.is_empty() {
            self.log(
                "error",
                "ask requires a question. Next: /ask what should I inspect?",
            );
            return;
        }
        if self.agent_chat.as_ref().is_some_and(|agent| agent.running) {
            self.log(
                "agent",
                "question already active; wait for the current answer",
            );
            return;
        }

        // Fold any previous turn into history before we mint the new
        // turn — gives multi-turn parity with `agent-chat.jsx::bubble`.
        let prior = self.agent_chat.as_ref().cloned().unwrap_or_default();
        let Some(model) = self.config.model.clone() else {
            self.shell_view = ShellView::AgentChat;
            let mut next = prior.fold_for_next_turn(question.to_string());
            next.error = Some(
                "ask requires an explicit model. Next: model, then choose a pi-agent-core provider/model".to_string(),
            );
            self.agent_chat = Some(next);
            self.log(
                "error",
                "ask requires an explicit model. Next: model, then choose a pi-agent-core provider/model",
            );
            return;
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.shell_view = ShellView::AgentChat;
            let mut next = prior.fold_for_next_turn(question.to_string());
            next.error = Some(message.clone());
            self.agent_chat = Some(next);
            self.log("error", message);
            return;
        }

        let cwd = self
            .target
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let config = self.config.clone();
        let thinking_level = self.session_thinking_level.clone();
        let question = question.to_string();
        let (tx, rx) = mpsc::channel();
        let mut next = prior.fold_for_next_turn(question.clone());
        next.running = true;
        // Mint a synthetic run id from wall-clock seconds so the
        // operator can `/trace agent-<n>` and the trace.jsonl is
        // findable by the runs ledger.  Same shape used by scan runs.
        let started_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        let agent_run_id = format!("agent-{started_secs}");
        next.run_id = Some(agent_run_id.clone());
        next.started_secs = started_secs;
        self.agent_chat = Some(next);
        self.agent_rx = Some(rx);
        self.shell_view = ShellView::AgentChat;
        self.log(
            "agent",
            format!(
                "asking {model}{}",
                thinking_level
                    .as_deref()
                    .map(|level| format!(" / {level}"))
                    .unwrap_or_default()
            ),
        );

        // Emit a `plan` step capturing the question that just dispatched
        // — gives the trace view a leading row even before the LLM
        // answers.
        append_trace_step(
            self.target.as_deref(),
            &agent_run_id,
            1,
            "plan",
            &format!("ask {} ({model})", short_label(&question, 80)),
            None,
            None,
        );
        // Drop a synthetic summary.json so `/runs` lists the agent run
        // alongside scan runs.  Best-effort write; failures are silent.
        write_run_summary(
            self.target.as_deref(),
            &agent_run_id,
            "running",
            None,
            self.target
                .as_ref()
                .map(|p| p.display().to_string())
                .as_deref()
                .unwrap_or("."),
        );

        thread::spawn(move || agent_worker(config, model, thinking_level, cwd, question, tx));
    }

    pub(crate) fn apply_agent_event(&mut self, event: AgentEvent) {
        let abort_requested = self
            .agent_chat
            .as_ref()
            .is_some_and(|agent| agent.abort_requested);
        let run_id = self
            .agent_chat
            .as_ref()
            .and_then(|agent| agent.run_id.clone());
        let started_secs = self
            .agent_chat
            .as_ref()
            .map(|agent| agent.started_secs)
            .unwrap_or(0);
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let latency_ms = if started_secs > 0 && now_secs >= started_secs {
            Some((now_secs - started_secs) * 1000)
        } else {
            None
        };
        match event {
            AgentEvent::Answered { text } => {
                if let Some(agent) = &mut self.agent_chat {
                    agent.running = false;
                    agent.abort_requested = false;
                    if abort_requested {
                        agent.answer = None;
                        agent.error =
                            Some("response arrived after abort request; ignored".to_string());
                    } else {
                        agent.answer = Some(text.clone());
                        agent.error = None;
                    }
                }
                if abort_requested {
                    self.log(
                        "agent",
                        "pi-agent-core response arrived after abort request; ignored",
                    );
                } else {
                    self.log("answer", text.clone());
                    // Emit `llm` step for the answer.  Cost lives on the
                    // session total (`record_cost` already updated it),
                    // so we don't double-report here.
                    if let Some(rid) = &run_id {
                        append_trace_step(
                            self.target.as_deref(),
                            rid,
                            2,
                            "llm",
                            &format!("answer ({} chars)", text.chars().count()),
                            latency_ms,
                            None,
                        );
                        write_run_summary(
                            self.target.as_deref(),
                            rid,
                            "complete",
                            None,
                            self.target
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .as_deref()
                                .unwrap_or("."),
                        );
                    }
                }
            }
            AgentEvent::Failed { error } => {
                if let Some(agent) = &mut self.agent_chat {
                    agent.running = false;
                    agent.abort_requested = false;
                    agent.answer = None;
                    if abort_requested {
                        agent.error = Some(format!(
                            "request ended after abort request; last error: {error}"
                        ));
                    } else {
                        agent.error = Some(error.clone());
                    }
                }
                if abort_requested {
                    self.log(
                        "agent",
                        format!("pi-agent-core ended after abort request: {error}"),
                    );
                } else {
                    self.log("error", error.clone());
                    if let Some(rid) = &run_id {
                        append_trace_step(
                            self.target.as_deref(),
                            rid,
                            2,
                            "refused",
                            &short_label(&error, 80),
                            latency_ms,
                            None,
                        );
                        write_run_summary(
                            self.target.as_deref(),
                            rid,
                            "failed",
                            None,
                            self.target
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .as_deref()
                                .unwrap_or("."),
                        );
                    }
                }
            }
        }
    }
}
