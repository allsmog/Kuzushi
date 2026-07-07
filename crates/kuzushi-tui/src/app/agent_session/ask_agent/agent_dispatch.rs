use super::agent_dispatch_model::{
    agent_cwd, agent_target_label, next_agent_run_id, spawn_agent_dispatch, thinking_level_suffix,
    AgentDispatchParts, AgentDispatchStart, AgentDispatchState,
};
use super::agent_prompt::agent_question_with_context;
use super::*;
use crate::ui_view_models::screen_context_model;
use kuzushi_core::run_artifacts::FailureToLlmContext;

impl ShellApp {
    pub(crate) fn ask_agent(&mut self, question: &str) {
        let effects = self.reduce_ask_agent(question);
        self.execute_effects(effects);
    }

    pub(crate) fn reduce_ask_agent(&mut self, question: &str) -> Vec<ShellEffect> {
        let Some(operator_question) = self.accept_agent_question(question) else {
            return Vec::new();
        };
        let prior = self.agent_chat.as_ref().cloned().unwrap_or_default();
        let Some(model) = self.agent_model_for_question(&prior, &operator_question) else {
            return Vec::new();
        };
        let dispatch = self.start_agent_dispatch(prior, operator_question, model);
        vec![ShellEffect::DispatchAgent(dispatch)]
    }

    pub(crate) fn dispatch_agent(&mut self, dispatch: AgentDispatch) {
        self.log_agent_dispatch(&dispatch);
        self.write_agent_dispatch_artifacts(&dispatch);
        self.log_agent_failure_context_attachment(dispatch.attached_failure_context);
        self.log_agent_screen_context_attachment(dispatch.attached_screen_context);
        let generation = dispatch.generation;
        let watchdog_cancel = dispatch.cancel.clone();
        let handle = spawn_agent_dispatch(dispatch, self.loop_wake.clone());
        self.register_worker_handle_with_watchdog("agent", generation, handle, watchdog_cancel);
    }

    fn accept_agent_question(&mut self, question: &str) -> Option<String> {
        let question = question.trim();
        if question.is_empty() {
            self.log(
                "error",
                "ask requires a question. Next: /ask what should I inspect?",
            );
            return None;
        }
        if self.agent_chat.as_ref().is_some_and(|agent| agent.running) {
            self.log(
                "agent",
                "question already active; wait for the current answer",
            );
            return None;
        }
        Some(question.to_string())
    }

    fn agent_model_for_question(
        &mut self,
        prior: &AgentChatView,
        question: &str,
    ) -> Option<String> {
        let Some(model) = self.config.model.clone() else {
            let message = "ask requires an explicit model. Next: model, then choose a LangGraph provider/model";
            self.show_agent_question_error(prior, question, message.to_string());
            return None;
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.show_agent_question_error(prior, question, message);
            return None;
        }
        Some(model)
    }

    fn show_agent_question_error(
        &mut self,
        prior: &AgentChatView,
        question: &str,
        message: String,
    ) {
        self.shell_view = ShellView::AgentChat;
        let mut next = prior.fold_for_next_turn(question.to_string());
        next.failure_context = prior.failure_context.clone();
        next.pending_failure_context = prior.pending_failure_context.clone();
        next.error = Some(message.clone());
        self.agent_chat = Some(next);
        self.log("error", message);
    }

    fn start_agent_dispatch(
        &mut self,
        prior: AgentChatView,
        operator_question: String,
        model: String,
    ) -> AgentDispatch {
        let start = self.prepare_agent_dispatch_start(prior, operator_question, model);
        self.install_agent_dispatch_state(start.state);
        self.agent_dispatch_from_parts(start.parts)
    }

    fn prepare_agent_dispatch_start(
        &mut self,
        prior: AgentChatView,
        operator_question: String,
        model: String,
    ) -> AgentDispatchStart {
        let screen_context = screen_context_model(self);
        let failure_context = self.take_pending_failure_context();
        let (tx, rx) = mpsc::channel();
        let cancel = ScanCancellation::default();
        let generation = self.next_worker_generation();
        let (run_id, started_secs) = next_agent_run_id();
        let agent_prompt = agent_question_with_context(
            &operator_question,
            failure_context.as_ref(),
            Some(&screen_context),
        );
        AgentDispatchStart::new(
            prior,
            operator_question,
            model,
            agent_prompt,
            run_id,
            started_secs,
            screen_context.scope_chip(),
            failure_context,
            tx,
            rx,
            generation,
            cancel,
        )
    }

    fn agent_dispatch_from_parts(&self, parts: AgentDispatchParts) -> AgentDispatch {
        AgentDispatch {
            config: self.config.clone(),
            model: parts.model,
            thinking_level: self.session_thinking_level.clone(),
            cwd: agent_cwd(self.target.as_ref()),
            operator_question: parts.operator_question,
            agent_prompt: parts.agent_prompt,
            run_id: parts.run_id,
            attached_failure_context: parts.attached_failure_context,
            attached_screen_context: true,
            tx: parts.tx,
            generation: parts.generation,
            cancel: parts.cancel,
        }
    }

    fn install_agent_dispatch_state(&mut self, state: AgentDispatchState) {
        let mut next = state.prior.fold_for_next_turn(state.operator_question);
        next.running = true;
        next.run_id = Some(state.run_id);
        next.started_secs = state.started_secs;
        next.screen_context_scope = state.screen_context_scope;
        next.failure_context = state.failure_context;
        self.agent_chat = Some(next);
        self.agent_generation = Some(state.generation);
        self.agent_rx = Some(state.rx);
        self.agent_cancel = Some(state.cancel);
        self.shell_view = ShellView::AgentChat;
    }

    pub(crate) fn set_pending_failure_context(&mut self, context: FailureToLlmContext) {
        let agent = self.agent_chat.get_or_insert_with(AgentChatView::default);
        agent.failure_context = Some(context.clone());
        agent.pending_failure_context = Some(context);
    }

    fn take_pending_failure_context(&mut self) -> Option<FailureToLlmContext> {
        self.agent_chat
            .as_mut()
            .and_then(|agent| agent.pending_failure_context.take())
    }

    fn log_agent_dispatch(&mut self, dispatch: &AgentDispatch) {
        self.log(
            "agent",
            format!(
                "asking {}{}",
                dispatch.model,
                thinking_level_suffix(dispatch.thinking_level.as_deref())
            ),
        );
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Thinking,
            "agent",
            format!("asking {}", dispatch.model),
        ));
    }

    fn write_agent_dispatch_artifacts(&self, dispatch: &AgentDispatch) {
        append_trace_step(
            self.target.as_deref(),
            &dispatch.run_id,
            1,
            "plan",
            &format!(
                "ask {} ({})",
                short_label(&dispatch.operator_question, 80),
                dispatch.model
            ),
            None,
            None,
        );
        let target_label = agent_target_label(self.target.as_ref());
        write_run_summary(
            self.target.as_deref(),
            &dispatch.run_id,
            "running",
            None,
            &target_label,
        );
    }

    fn log_agent_failure_context_attachment(&mut self, attached: bool) {
        if attached {
            self.log(
                "failure-context",
                "attached bounded failure handoff to agent prompt",
            );
        }
    }

    fn log_agent_screen_context_attachment(&mut self, attached: bool) {
        if attached {
            self.log(
                "agent",
                "attached bounded untrusted screen context to agent prompt",
            );
        }
    }
}
