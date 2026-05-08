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
}
