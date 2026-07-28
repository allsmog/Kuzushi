use self::dispatch::{
    persist_background_tool_preparation_rejection, persist_background_tool_run_start,
    prepare_background_tool_dispatch, BackgroundToolDispatch, BackgroundToolRun,
    BackgroundToolRunSeed, BackgroundToolWorkerLaunch,
};
use self::preflight::langgraph_bridge_preflight_error;
use super::*;

mod dispatch;
mod preflight;

impl ShellApp {
    #[cfg(test)]
    pub(crate) fn start_background_tool(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
    ) {
        self.start_authorized_background_tool(
            tool_name,
            input,
            workspace,
            status,
            thinking_level,
            ExecutionAuthorization::default(),
        );
    }

    pub(crate) fn start_authorized_background_tool(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
        authorization: ExecutionAuthorization,
    ) {
        let prepared = match self.prepare_background_tool_input(&tool_name, input, &workspace) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.log("error", format!("{tool_name} input invalid: {error}"));
                return;
            }
        };
        self.start_prepared_background_tool_with_activity_and_authorization(
            tool_name,
            prepared,
            workspace,
            status,
            thinking_level,
            None,
            authorization,
        );
    }

    pub(crate) fn start_background_tool_with_activity(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
        activity: Option<LiveActivity>,
    ) {
        let prepared = match self.prepare_background_tool_input(&tool_name, input, &workspace) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.log("error", format!("{tool_name} input invalid: {error}"));
                return;
            }
        };
        self.start_prepared_background_tool_with_activity_and_authorization(
            tool_name,
            prepared,
            workspace,
            status,
            thinking_level,
            activity,
            ExecutionAuthorization::default(),
        );
    }

    pub(crate) fn start_authorized_prepared_background_tool(
        &mut self,
        tool_name: String,
        input: PreparedToolInput,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
        authorization: ExecutionAuthorization,
    ) {
        self.start_prepared_background_tool_with_activity_and_authorization(
            tool_name,
            input,
            workspace,
            status,
            thinking_level,
            None,
            authorization,
        );
    }

    fn start_prepared_background_tool_with_activity_and_authorization(
        &mut self,
        tool_name: String,
        input: PreparedToolInput,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
        activity: Option<LiveActivity>,
        authorization: ExecutionAuthorization,
    ) {
        if self.reject_prepared_background_tool_launch(&workspace, &tool_name, &input) {
            return;
        }
        let Some(seed) = self.initialize_background_tool_run(&workspace, &tool_name, &input) else {
            return;
        };
        let run_id = seed.run_id.clone();
        let runtime_backed =
            self.registry()
                .tool_wants_runtime(&tool_name, input.value(), self.config());
        let Some(ticket) = self.try_start_exclusive_job(JobKind::Run, tool_name.clone()) else {
            return;
        };
        self.begin_run_cost_tracking(&run_id, runtime_backed);
        let Some(dispatch) = self.background_tool_dispatch(seed, ticket) else {
            return;
        };
        self.launch_prepared_background_tool(
            dispatch,
            workspace,
            tool_name,
            input,
            thinking_level,
            status,
            activity,
            authorization,
        );
        self.open_activity_for_started_background_tool();
    }

    fn reject_prepared_background_tool_launch(
        &mut self,
        workspace: &WorkspaceTarget,
        tool_name: &str,
        input: &PreparedToolInput,
    ) -> bool {
        if input.tool_name() != tool_name {
            self.log(
                "error",
                format!(
                    "{tool_name} launch rejected: prepared input belongs to {}",
                    input.tool_name()
                ),
            );
            return true;
        }
        self.reject_background_tool_launch(workspace, tool_name, input.value())
    }

    fn initialize_background_tool_run(
        &mut self,
        workspace: &WorkspaceTarget,
        tool_name: &str,
        input: &PreparedToolInput,
    ) -> Option<BackgroundToolRunSeed> {
        let mut seed = match self.background_tool_run_seed(workspace, tool_name, input.value()) {
            Ok(seed) => seed,
            Err(error) => {
                self.report_tool_launch_persistence_failure(tool_name, error);
                return None;
            }
        };
        seed.phase = background_tool_origin_phase(
            tool_name,
            self.engagement.current_phase(),
            self.engagement.running_tool(),
        );
        seed.attempt_id = seed
            .phase
            .map(|_| kuzushi_core::run_lifecycle::RunAttemptId::new());
        Some(seed)
    }

    fn reject_background_tool_launch(
        &mut self,
        workspace: &WorkspaceTarget,
        tool_name: &str,
        input: &serde_json::Value,
    ) -> bool {
        let runtime_backed = self
            .registry()
            .tool_wants_runtime(tool_name, input, self.config());
        if self.reject_runtime_launch_while_budget_halted(runtime_backed, tool_name) {
            return true;
        }
        self.reject_background_tool_state(workspace, tool_name, input)
    }

    fn reject_background_tool_state(
        &mut self,
        workspace: &WorkspaceTarget,
        tool_name: &str,
        input: &serde_json::Value,
    ) -> bool {
        if self.tool_launch_blocked(tool_name) {
            return true;
        }
        if self.reject_pending_prompt_mutation(workspace, tool_name) {
            return true;
        }
        self.reject_langgraph_background_tool_launch(tool_name, input)
    }

    fn reject_langgraph_background_tool_launch(
        &mut self,
        tool_name: &str,
        input: &serde_json::Value,
    ) -> bool {
        let Some(error) = self.langgraph_background_tool_launch_blocker(tool_name, input) else {
            return false;
        };
        self.log("error", error);
        true
    }

    fn background_tool_dispatch(
        &self,
        seed: BackgroundToolRunSeed,
        ticket: JobTicket,
    ) -> Option<BackgroundToolDispatch> {
        prepare_background_tool_dispatch(self.registry(), self.config(), seed, ticket)
    }

    fn background_tool_run_seed(
        &self,
        workspace: &WorkspaceTarget,
        tool_name: &str,
        input: &serde_json::Value,
    ) -> anyhow::Result<BackgroundToolRunSeed> {
        persist_background_tool_run_start(
            self.registry(),
            self.config(),
            workspace,
            tool_name,
            input,
        )
    }

    fn report_tool_launch_persistence_failure(&mut self, tool_name: &str, error: anyhow::Error) {
        let message =
            format!("{tool_name} launch blocked: could not initialize run artifacts: {error}");
        self.log("error", message.clone());
        self.set_error_notice("artifacts", message);
        self.set_failed_activity(
            tool_name.to_string(),
            "run artifact initialization failed; no worker was started",
        );
    }

    fn launch_prepared_background_tool(
        &mut self,
        dispatch: BackgroundToolDispatch,
        workspace: WorkspaceTarget,
        tool_name: String,
        input: PreparedToolInput,
        thinking_level: Option<String>,
        status: &str,
        activity: Option<LiveActivity>,
        authorization: ExecutionAuthorization,
    ) {
        let model_override = active_model_override_from_input(input.value(), &dispatch.config);
        BackgroundToolWorkerLaunch::from_dispatch(
            dispatch,
            workspace,
            tool_name,
            input,
            thinking_level,
            authorization,
        )
        .attach_and_start(self, status, activity, model_override);
    }

    pub(crate) fn prepare_background_tool_input(
        &self,
        tool_name: &str,
        input: serde_json::Value,
        workspace: &WorkspaceTarget,
    ) -> anyhow::Result<PreparedToolInput> {
        let ctx = ToolExecutionContext {
            config: self.config(),
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        self.registry()
            .prepare_dispatch_input(tool_name, input.clone(), &ctx, Some(self.option_store()))
            .map_err(|error| {
                self.background_tool_preparation_error(workspace, tool_name, &input, error)
            })
    }

    pub(super) fn background_tool_preparation_error(
        &self,
        workspace: &WorkspaceTarget,
        tool_name: &str,
        input: &serde_json::Value,
        error: anyhow::Error,
    ) -> anyhow::Error {
        let detail = error.to_string();
        match persist_background_tool_preparation_rejection(
            self.registry(),
            self.config(),
            workspace,
            tool_name,
            input,
            &detail,
        ) {
            Ok(_) => error,
            Err(persistence) => error.context(format!(
                "also could not persist the rejected shell run: {persistence:#}"
            )),
        }
    }

    fn reject_pending_prompt_mutation(
        &mut self,
        workspace: &WorkspaceTarget,
        tool_name: &str,
    ) -> bool {
        let (module_id, verb) = tool_name.split_once(':').unwrap_or((tool_name, "run"));
        match kuzushi_core::latest_prompt_mutation(workspace, module_id, verb) {
            Ok(Some(mutation))
                if mutation.status == kuzushi_core::PromptMutationStatus::Pending =>
            {
                self.set_focused_module(Some(module_id.to_string()));
                self.set_shell_view(ShellView::PromptsEditor);
                self.log(
                    "prompt",
                    format!(
                        "{tool_name} blocked by pending prompt mutation {}; approve or reject it first",
                        mutation.id
                    ),
                );
                true
            }
            Ok(_) => false,
            Err(error) => {
                self.set_shell_view(ShellView::PromptsEditor);
                self.log(
                    "error",
                    format!("could not read prompt mutations before {tool_name}: {error}"),
                );
                true
            }
        }
    }

    pub(crate) fn langgraph_background_tool_launch_blocker(
        &self,
        tool_name: &str,
        input: &serde_json::Value,
    ) -> Option<String> {
        if !self
            .registry()
            .tool_wants_runtime(tool_name, input, self.config())
        {
            return None;
        }
        langgraph_bridge_preflight_error(self.config(), tool_name)
    }

    fn open_activity_for_started_background_tool(&mut self) {
        // Auto-open AFTER the worker thread spawns. Earlier, the flip happened
        // before the worker existed, so a fast dispatch error could strand the
        // operator on an empty Activity view. Flipping after thread::spawn
        // guarantees the run is in flight before the view becomes visible.
        if self.run_focus_is_background_owned() {
            return;
        }
        let committed_plan = self.engagement.running_tool().is_some();
        if self.ui().auto_open_activity() || committed_plan {
            self.set_shell_view(ShellView::Activity);
            self.set_input_mode(InputMode::Navigate);
            self.log(
                "view",
                "opened activity — Ctrl+C requests abort; type `back` to leave (disable: setg ui.auto_open_activity false)",
            );
        }
    }

    fn attach_background_tool_run(
        &mut self,
        run: &BackgroundToolRun,
        cancel: ScanCancellation,
        tool_name: &str,
        status: &str,
        activity: Option<LiveActivity>,
        model_override: Option<String>,
    ) {
        self.set_target(Some(run.target.clone()));
        let session = self.background_activity_session(run, tool_name);
        self.set_activity(Some(session));
        self.record_session_event(kuzushi_core::session_transcript::SessionEvent::RunStarted {
            run_id: run.run_id.clone(),
            tool_name: tool_name.to_string(),
        });
        self.start_tool_run(
            tool_name.to_string(),
            cancel,
            run.run_id.clone(),
            run.target.clone(),
            model_override,
        );
        self.log(
            "tool",
            format!(
                "running {tool_name} in background; {status} under {} · run {}",
                run.target_label, run.run_id
            ),
        );
        self.set_live_activity(
            activity.unwrap_or_else(|| live_activity_for_tool(tool_name, status)),
        );
    }

    fn background_activity_session(
        &self,
        run: &BackgroundToolRun,
        tool_name: &str,
    ) -> ActivitySession {
        let mut session = ActivitySession::new(run.run_id.clone());
        if let Some(phase) = run.phase {
            session = session.with_origin_phase(phase);
        }
        if let Some(attempt_id) = run.attempt_id {
            session = session.with_phase_attempt_id(attempt_id);
        }
        session = self.capture_run_focus_origin(session);
        session.seed_task_sequence(self.engagement.planning_tool_sequence());
        self.bind_background_session_task(&mut session, run, tool_name);
        session
    }

    fn bind_background_session_task(
        &self,
        session: &mut ActivitySession,
        run: &BackgroundToolRun,
        tool_name: &str,
    ) {
        let Some(task) = self.engagement.running_planning_task() else {
            // Chain, steer, and ad hoc launches can still match one seeded row.
            session.alias_tool_to_unique_planned_row(tool_name);
            if let Some(activity_task_id) = session.task_id_for_bound_tool(tool_name) {
                session.bind_lifecycle_task(run.task_id, activity_task_id);
            }
            return;
        };
        let activity_task_id = task.activity_task_id();
        session.bind_tool_task(tool_name, activity_task_id.clone());
        session.bind_lifecycle_task(run.task_id, activity_task_id);
    }
}

fn background_tool_origin_phase(
    tool_name: &str,
    current_phase: Option<crate::app::WorkflowPhase>,
    planning_tool: Option<&str>,
) -> Option<crate::app::WorkflowPhase> {
    let declared_phase = kuzushi_core::modules::autonomy::tool_phase(tool_name);
    declared_phase.or_else(|| {
        planning_tool
            .is_some_and(|planned| planned == tool_name)
            .then_some(current_phase)
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_owned_plan_completion_keeps_setup_and_receipt() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Setup);
        app.set_input_mode(InputMode::Navigate);
        app.engagement.set_phase(crate::app::WorkflowPhase::Map);

        let session = app.capture_run_focus_origin(ActivitySession::new("map-first"));
        app.set_activity(Some(session));
        app.set_shell_view(ShellView::Activity);
        app.engagement
            .set_running_tool("repository:inventory".to_string());
        app.background_handoff();

        let continuation = app.capture_run_focus_origin(ActivitySession::new("map-final"));
        app.set_activity(Some(continuation));
        app.engagement.set_running_tool("secrets:scan".to_string());
        app.open_activity_for_started_background_tool();

        assert_eq!(app.shell_view(), ShellView::Setup);
        assert!(app.run_focus_is_background_owned());

        app.set_running_tool_for_test("secrets:scan");
        app.apply_job_event(ShellEvent::Tool(ToolEvent::Finished {
            tool_name: "secrets:scan".to_string(),
            result: serde_json::json!({ "output": "no secrets found" }),
        }));

        assert_eq!(app.shell_view(), ShellView::Setup);
        assert_eq!(
            app.engagement.current_phase(),
            Some(crate::app::WorkflowPhase::Scan)
        );
        assert!(app.activity().is_some_and(|session| {
            session.run_focus_backgrounded
                && session
                    .run_focus_receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.outcome == "completed" && receipt.run_count == 2)
        }));
    }

    #[test]
    fn committed_plan_opens_run_focus_even_when_ad_hoc_auto_open_is_disabled() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.ui_mut().set_auto_open_activity(false);
        app.set_shell_view(ShellView::Setup);
        app.engagement
            .set_running_tool("repository:inventory".to_string());

        app.open_activity_for_started_background_tool();

        assert_eq!(app.shell_view(), ShellView::Activity);
        assert_eq!(app.input_mode(), InputMode::Navigate);
    }

    #[test]
    fn declared_tool_phase_wins_over_a_different_walker_phase() {
        assert_eq!(
            background_tool_origin_phase(
                "semgrep:scan",
                Some(crate::app::WorkflowPhase::Fix),
                Some("semgrep:scan"),
            ),
            Some(crate::app::WorkflowPhase::Scan)
        );
    }

    #[test]
    fn manual_generic_tool_ignores_a_residual_walker_phase() {
        assert_eq!(
            background_tool_origin_phase(
                "findings:list",
                Some(crate::app::WorkflowPhase::Scan),
                None,
            ),
            None
        );
    }

    #[test]
    fn planning_owned_generic_tool_captures_the_current_walker_phase() {
        assert_eq!(
            background_tool_origin_phase(
                "findings:list",
                Some(crate::app::WorkflowPhase::Prove),
                Some("findings:list"),
            ),
            Some(crate::app::WorkflowPhase::Prove)
        );
    }

    #[test]
    fn new_phase_run_does_not_reuse_a_completed_activity_attempt_id() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        let stale_attempt_id = kuzushi_core::run_lifecycle::RunAttemptId::new();
        let mut completed =
            ActivitySession::for_phase("prior-scan", crate::app::WorkflowPhase::Scan)
                .with_phase_attempt_id(stale_attempt_id);
        completed.mark_run_focus_terminal_pending("completed");
        completed.run_focus_terminal_pending = false;
        app.set_activity(Some(completed));
        let prepared = app
            .prepare_background_tool_input(
                "secret-scan:scan",
                serde_json::json!({ "target": target.path() }),
                &workspace,
            )
            .unwrap();

        let first = app
            .initialize_background_tool_run(&workspace, "secret-scan:scan", &prepared)
            .unwrap();
        let second = app
            .initialize_background_tool_run(&workspace, "secret-scan:scan", &prepared)
            .unwrap();

        assert_eq!(first.phase, Some(crate::app::WorkflowPhase::Scan));
        assert_ne!(first.attempt_id, Some(stale_attempt_id));
        assert_ne!(first.attempt_id, second.attempt_id);
    }

    #[test]
    fn active_run_focus_continuation_preserves_its_attempt_id() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let attempt_id = kuzushi_core::run_lifecycle::RunAttemptId::new();
        let prior = app.capture_run_focus_origin(
            ActivitySession::for_phase("prior-scan", crate::app::WorkflowPhase::Scan)
                .with_phase_attempt_id(attempt_id),
        );
        app.set_activity(Some(prior));
        app.set_shell_view(ShellView::Activity);

        let continued = app.capture_run_focus_origin(
            ActivitySession::for_phase("continued-scan", crate::app::WorkflowPhase::Scan)
                .with_phase_attempt_id(kuzushi_core::run_lifecycle::RunAttemptId::new()),
        );

        assert_eq!(
            continued.origin_phase,
            Some(crate::app::WorkflowPhase::Scan)
        );
        assert_eq!(continued.phase_attempt_id, Some(attempt_id));
    }

    #[test]
    fn optional_runtime_preflight_matches_worker_runtime_construction() {
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-test".to_string());
        config.runtime.langgraph_bridge_command = Some(Vec::new());
        let app = ShellApp::new(config, None);

        let blocked = app
            .langgraph_background_tool_launch_blocker("threat-model:build", &serde_json::json!({}));

        assert!(blocked.is_some_and(|message| message.contains("requires LangGraph")));
    }
}
