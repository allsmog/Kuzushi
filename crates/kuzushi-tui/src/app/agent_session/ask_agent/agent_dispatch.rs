use super::agent_dispatch_model::{next_agent_run_id, spawn_agent_dispatch, thinking_level_suffix};
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
        let Some(dispatch) = self.start_agent_dispatch(prior, operator_question, model) else {
            return Vec::new();
        };
        vec![ShellEffect::DispatchAgent(dispatch)]
    }

    pub(crate) fn dispatch_agent(&mut self, dispatch: AgentDispatch) {
        if self.has_running_work() {
            self.log(
                "agent",
                "agent launch blocked — finish or cancel the active work, then retry",
            );
            self.set_waiting_activity("agent", "another run owns the background execution slot");
            return;
        }
        if let Err(error) = self.write_agent_dispatch_artifacts(&dispatch) {
            self.report_agent_launch_persistence_failure(&dispatch, error);
            return;
        }
        let Some(ticket) = self.try_start_exclusive_job(JobKind::Agent, "agent") else {
            return;
        };
        let generation = ticket.generation();
        let watchdog_cancel = ticket.cancel.clone();
        self.set_activity(Some(ActivitySession::for_optional_phase(
            dispatch.run_id.clone(),
            dispatch.origin_phase,
        )));
        self.install_agent_dispatch_state(&dispatch, watchdog_cancel.clone());
        self.log_agent_dispatch(&dispatch);
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
    ) -> Option<AgentDispatch> {
        let target = self.agent_target_for_question(&prior, &operator_question)?;
        let screen_context = screen_context_model(self);
        let failure_context = self.take_pending_failure_context();
        let (run_id, started_secs) = next_agent_run_id();
        let agent_prompt = agent_question_with_context(
            &operator_question,
            failure_context.as_ref(),
            Some(&screen_context),
        );
        Some(self.agent_dispatch(
            prior,
            operator_question,
            model,
            target,
            agent_prompt,
            run_id,
            started_secs,
            screen_context.scope_chip(),
            failure_context,
        ))
    }

    fn agent_target_for_question(
        &mut self,
        prior: &AgentChatView,
        question: &str,
    ) -> Option<PathBuf> {
        self.target_owned().or_else(|| {
            self.show_agent_question_error(
                prior,
                question,
                "ask requires an explicit target. Next: target <path> (or target .)".to_string(),
            );
            None
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn agent_dispatch(
        &self,
        prior: AgentChatView,
        operator_question: String,
        model: String,
        target: PathBuf,
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
            cwd: target.clone(),
            artifact_target: target,
            prior,
            operator_question,
            agent_prompt,
            run_id,
            started_secs,
            origin_phase: self.engagement.current_phase(),
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
        self.set_agent_artifact_target(Some(dispatch.artifact_target.clone()));
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

    fn write_agent_dispatch_artifacts(&self, dispatch: &AgentDispatch) -> anyhow::Result<()> {
        let input = serde_json::json!({
            "question": dispatch.operator_question,
            "thinkingLevel": dispatch.thinking_level,
            "screenContextScope": dispatch.screen_context_scope,
            "failureContextAttached": dispatch.attached_failure_context,
            "screenContextAttached": dispatch.attached_screen_context,
        });
        record_agent_run_started(
            Some(dispatch.artifact_target.as_path()),
            &dispatch.run_id,
            &input,
            dispatch.model.clone(),
            kuzushi_core::config_hash(&dispatch.config).ok(),
            self.registry().loaded_module_specifiers(),
        )?;
        append_trace_step(
            Some(dispatch.artifact_target.as_path()),
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
        Ok(())
    }

    fn report_agent_launch_persistence_failure(
        &mut self,
        dispatch: &AgentDispatch,
        error: anyhow::Error,
    ) {
        if let Some(context) = dispatch.failure_context.clone() {
            self.set_pending_failure_context(context);
        }
        let message = format!("agent launch blocked: could not initialize run artifacts: {error}");
        self.log("error", message.clone());
        self.set_error_notice("artifacts", message);
        self.set_failed_activity(
            "agent",
            "run artifact initialization failed; no worker was started",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent_model() -> String {
        ["openai", "gpt-test"].join(":")
    }

    fn agent_test_app(target: &std::path::Path, model: &str) -> ShellApp {
        let mut app = ShellApp::new(
            V2Config {
                model: Some(model.to_string()),
                ..V2Config::default()
            },
            None,
        );
        app.set_target(Some(target.to_path_buf()));
        app
    }

    fn seed_agent_run(app: &mut ShellApp, model: &str) -> String {
        let dispatch = app
            .start_agent_dispatch(
                AgentChatView::default(),
                "what changed?".to_string(),
                model.to_string(),
            )
            .expect("explicit target should produce dispatch");
        let run_id = dispatch.run_id.clone();
        app.install_agent_dispatch_state(&dispatch, ScanCancellation::default());
        app.write_agent_dispatch_artifacts(&dispatch).unwrap();
        run_id
    }

    fn answered_agent_record(app: &mut ShellApp, model: &str) -> AgentRunRecord {
        app.apply_agent_event(AgentEvent::Answered {
            text: "usable answer".to_string(),
            audit: AgentCallAudit::for_prompt(model, "system", "what changed?"),
        })
        .into_iter()
        .find_map(|effect| match effect {
            ShellEffect::RecordAgentRun(record) => Some(record),
            _ => None,
        })
        .expect("terminal agent record")
    }

    fn assert_partial_agent_artifact_failure(
        app: &ShellApp,
        target: &std::path::Path,
        run_id: &str,
    ) {
        assert_eq!(
            app.agent_chat().and_then(|agent| agent.answer.as_deref()),
            Some("usable answer")
        );
        assert_eq!(
            app.live_activity().map(|activity| activity.phase),
            Some(LiveActivityPhase::Partial)
        );
        assert!(app.log_lines().iter().any(|line| {
            line.prefix == "error"
                && line.body.contains("result retained")
                && line.body.contains("could not be finalized")
        }));
        assert_eq!(
            app.advisory().notice.as_ref().map(|notice| notice.severity),
            Some(NoticeSeverity::Error)
        );
        assert_eq!(
            kuzushi_core::load_run_summary(target, run_id)
                .unwrap()
                .status,
            "running"
        );
    }

    #[test]
    fn agent_dispatch_captures_only_an_explicit_guided_phase() {
        let target = tempfile::tempdir().expect("target");
        let model = test_agent_model();
        let mut app = agent_test_app(target.path(), &model);

        let manual = app
            .start_agent_dispatch(
                AgentChatView::default(),
                "explain this target".to_string(),
                model.clone(),
            )
            .expect("explicit target should produce dispatch");
        assert_eq!(manual.origin_phase, None);

        app.engagement.set_phase(WorkflowPhase::Hunt);
        let guided = app
            .start_agent_dispatch(
                AgentChatView::default(),
                "steer the hunt".to_string(),
                model,
            )
            .expect("explicit target should produce dispatch");
        assert_eq!(guided.origin_phase, Some(WorkflowPhase::Hunt));
    }

    #[test]
    fn targetless_agent_question_is_refused_without_dispatch_or_artifacts() {
        let model = test_agent_model();
        let mut app = ShellApp::new(
            V2Config {
                model: Some(model),
                ..V2Config::default()
            },
            None,
        );

        assert!(app.reduce_ask_agent("inspect auth").is_empty());
        assert!(app
            .agent_chat()
            .and_then(|agent| agent.error.as_deref())
            .is_some_and(|error| error.contains("requires an explicit target")));
        assert!(app.agent_artifact_target_owned().is_none());
    }

    #[test]
    fn agent_terminal_artifacts_use_the_target_captured_at_dispatch() {
        let launch_target = tempfile::tempdir().expect("launch target");
        let later_target = tempfile::tempdir().expect("later target");
        let model = test_agent_model();
        let mut app = agent_test_app(launch_target.path(), &model);
        let run_id = seed_agent_run(&mut app, &model);

        // Bypass the public admission guard to model an unexpected concurrent
        // session mutation. Artifact ownership must still remain at launch A.
        app.session_mut()
            .set_target(Some(later_target.path().to_path_buf()));
        let record = answered_agent_record(&mut app, &model);
        assert_eq!(record.target.as_deref(), Some(launch_target.path()));

        app.record_agent_run_effect(record);
        let summary = kuzushi_core::load_run_summary(launch_target.path(), &run_id)
            .expect("launch-target summary");
        assert_eq!(summary.status, "completed");
        assert_eq!(summary.target, launch_target.path().display().to_string());
        assert!(kuzushi_core::run_dir(launch_target.path(), &run_id).is_dir());
        assert!(kuzushi_core::load_run_summary(later_target.path(), &run_id).is_err());
        assert!(!kuzushi_core::run_dir(later_target.path(), &run_id).exists());
    }

    #[test]
    fn agent_start_artifact_failure_blocks_worker_launch() {
        let target = tempfile::tempdir().expect("target");
        let model = test_agent_model();
        let mut app = ShellApp::new(
            V2Config {
                model: Some(model.clone()),
                ..V2Config::default()
            },
            None,
        );
        app.set_target(Some(target.path().to_path_buf()));
        let runs_root = kuzushi_core::runs_root(target.path());
        std::fs::create_dir_all(runs_root.parent().unwrap()).unwrap();
        std::fs::write(&runs_root, "path collision").unwrap();
        let dispatch = app
            .start_agent_dispatch(AgentChatView::default(), "what changed?".to_string(), model)
            .expect("explicit target should produce dispatch");

        app.dispatch_agent(dispatch);

        assert!(!app.jobs().is_running(JobKind::Agent));
        assert!(!app.agent_chat().is_some_and(|agent| agent.running));
        assert_eq!(
            app.live_activity().map(|activity| activity.phase),
            Some(LiveActivityPhase::Failed)
        );
        assert!(app.log_lines().iter().any(|line| {
            line.prefix == "error"
                && line.body.contains("launch blocked")
                && line.body.contains("run artifacts")
        }));
        assert_eq!(
            app.advisory().notice.as_ref().map(|notice| notice.severity),
            Some(NoticeSeverity::Error)
        );
    }

    #[test]
    fn agent_terminal_artifact_failure_retains_answer_and_marks_activity_partial() {
        let target = tempfile::tempdir().expect("target");
        let model = test_agent_model();
        let mut app = agent_test_app(target.path(), &model);
        let run_id = seed_agent_run(&mut app, &model);
        std::fs::create_dir(kuzushi_core::run_dir(target.path(), &run_id).join("result.json"))
            .unwrap();

        let record = answered_agent_record(&mut app, &model);
        app.record_agent_run_effect(record);
        assert_partial_agent_artifact_failure(&app, target.path(), &run_id);
    }
}
