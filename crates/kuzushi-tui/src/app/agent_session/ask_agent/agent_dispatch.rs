use super::agent_dispatch_model::{
    agent_cwd, agent_target_label, next_agent_run_id, spawn_agent_dispatch, thinking_level_suffix,
};
use super::agent_prompt::agent_question_with_context;
use super::*;
use crate::ui_view_models::screen_context_model;
use kuzushi_core::run_artifacts::FailureToLlmContext;

impl ShellApp {
    pub(crate) fn reduce_ask_agent(&mut self, question: &str) -> Vec<ShellEffect> {
        let Some(operator_question) = self.accept_agent_question(question) else {
            return Vec::new();
        };
        let prior = self.agent_chat().cloned().unwrap_or_default();
        let Some(model) = self.agent_model_for_question(&prior, &operator_question) else {
            return Vec::new();
        };
        let dispatch = self.start_agent_dispatch(prior, operator_question, model);
        vec![ShellEffect::DispatchAgent(dispatch)]
    }

    pub(crate) fn dispatch_agent(&mut self, dispatch: AgentDispatch) {
        let ticket = self.jobs_mut().start(JobKind::Agent, "agent");
        let generation = ticket.generation();
        let watchdog_cancel = ticket.cancel.clone();
        self.install_agent_dispatch_state(&dispatch, watchdog_cancel.clone());
        self.log_agent_dispatch(&dispatch);
        self.write_agent_dispatch_artifacts(&dispatch);
        self.log_agent_failure_context_attachment(dispatch.attached_failure_context);
        self.log_agent_screen_context_attachment(dispatch.attached_screen_context);
        let handle = spawn_agent_dispatch(dispatch, ticket);
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
        if self.agent_chat().is_some_and(|agent| agent.running) {
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
        let Some(model) = self.config().model.clone() else {
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
        self.set_shell_view(ShellView::AgentChat);
        let mut next = prior.fold_for_next_turn(question.to_string());
        next.failure_context = prior.failure_context.clone();
        next.pending_failure_context = prior.pending_failure_context.clone();
        next.error = Some(message.clone());
        self.set_agent_chat(Some(next));
        self.log("error", message);
    }

    fn start_agent_dispatch(
        &mut self,
        prior: AgentChatView,
        operator_question: String,
        model: String,
    ) -> AgentDispatch {
        let screen_context = screen_context_model(self);
        let failure_context = self.take_pending_failure_context();
        let (run_id, started_secs) = next_agent_run_id();
        let agent_prompt = agent_question_with_context(
            &operator_question,
            failure_context.as_ref(),
            Some(&screen_context),
        );
        self.agent_dispatch(
            prior,
            operator_question,
            model,
            agent_prompt,
            run_id,
            started_secs,
            screen_context.scope_chip(),
            failure_context,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn agent_dispatch(
        &self,
        prior: AgentChatView,
        operator_question: String,
        model: String,
        agent_prompt: String,
        run_id: String,
        started_secs: u64,
        screen_context_scope: Option<String>,
        failure_context: Option<FailureToLlmContext>,
    ) -> AgentDispatch {
        let attached_failure_context = failure_context.is_some();
        AgentDispatch {
            config: self.config().clone(),
            model,
            thinking_level: self.session_thinking_level_owned(),
            cwd: agent_cwd(self.target_path_buf()),
            prior,
            operator_question,
            agent_prompt,
            run_id,
            started_secs,
            screen_context_scope,
            failure_context,
            attached_failure_context,
            attached_screen_context: true,
        }
    }

    fn install_agent_dispatch_state(&mut self, dispatch: &AgentDispatch, cancel: ScanCancellation) {
        let mut next = dispatch
            .prior
            .clone()
            .fold_for_next_turn(dispatch.operator_question.clone());
        next.running = true;
        next.run_id = Some(dispatch.run_id.clone());
        next.started_secs = dispatch.started_secs;
        next.screen_context_scope = dispatch.screen_context_scope.clone();
        next.failure_context = dispatch.failure_context.clone();
        self.set_agent_chat(Some(next));
        self.set_agent_cancel(Some(cancel));
        self.set_shell_view(ShellView::AgentChat);
    }

    pub(crate) fn set_pending_failure_context(&mut self, context: FailureToLlmContext) {
        let agent = self.agent_chat_or_default_mut();
        agent.failure_context = Some(context.clone());
        agent.pending_failure_context = Some(context);
    }

    fn take_pending_failure_context(&mut self) -> Option<FailureToLlmContext> {
        self.agent_chat_mut()
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
            self.target(),
            &dispatch.run_id,
            "plan",
            &format!(
                "ask {} ({})",
                short_label(&dispatch.operator_question, 80),
                dispatch.model
            ),
            None,
            None,
        );
        let target_label = agent_target_label(self.target_path_buf());
        write_run_summary(
            self.target(),
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
