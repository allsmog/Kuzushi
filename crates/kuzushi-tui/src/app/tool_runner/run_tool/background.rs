use self::dispatch::{
    persist_background_tool_run_start, prepare_background_tool_dispatch, BackgroundToolDispatch,
    BackgroundToolRun, BackgroundToolRunSeed, BackgroundToolWorkerLaunch,
};
use self::preflight::langgraph_bridge_preflight_error;
use super::*;

mod dispatch;
mod preflight;

impl ShellApp {
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
        self.start_background_tool_with_activity_and_authorization(
            tool_name,
            input,
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
        self.start_background_tool_with_activity_and_authorization(
            tool_name,
            input,
            workspace,
            status,
            thinking_level,
            activity,
            ExecutionAuthorization::default(),
        );
    }

    fn start_background_tool_with_activity_and_authorization(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        status: &'static str,
        thinking_level: Option<String>,
        activity: Option<LiveActivity>,
        authorization: ExecutionAuthorization,
    ) {
        if self.reject_background_tool_launch(&workspace, &tool_name, &input) {
            return;
        }

        let seed = match self.background_tool_run_seed(&workspace, &tool_name, &input) {
            Ok(seed) => seed,
            Err(error) => {
                self.report_tool_launch_persistence_failure(&tool_name, error);
                return;
            }
        };
        let Some(ticket) = self.try_start_exclusive_job(JobKind::Run, tool_name.clone()) else {
            return;
        };
        let dispatch = self.background_tool_dispatch(seed, ticket);
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

    fn reject_background_tool_launch(
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
        if let Some(error) = self.langgraph_background_tool_launch_blocker(tool_name, input) {
            self.log("error", error);
            return true;
        }
        false
    }

    fn background_tool_dispatch(
        &self,
        seed: BackgroundToolRunSeed,
        ticket: JobTicket,
    ) -> BackgroundToolDispatch {
        prepare_background_tool_dispatch(
            self.registry(),
            self.config(),
            seed,
            ticket,
            self.jobs().trace_budget(),
        )
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
        input: serde_json::Value,
        thinking_level: Option<String>,
        status: &str,
        activity: Option<LiveActivity>,
        authorization: ExecutionAuthorization,
    ) {
        let model_override = active_model_override_from_input(&input, &dispatch.config);
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
        if self.ui().auto_open_activity() {
            self.set_shell_view(ShellView::Activity);
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
        let mut session = ActivitySession::new(run.run_id.clone());
        if let Some(phase) = background_tool_origin_phase(
            tool_name,
            self.engagement.current_phase(),
            self.engagement.running_tool(),
        ) {
            session = session.with_origin_phase(phase);
        }
        self.set_activity(Some(session));
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
    fn declared_tool_phase_wins_over_a_different_walker_phase() {
        assert_eq!(
            background_tool_origin_phase(
                "semgrep:scan",
                Some(crate::app::WorkflowPhase::Fix),
                Some("semgrep:scan"),
            ),
            Some(crate::app::WorkflowPhase::Hunt)
        );
    }

    #[test]
    fn manual_generic_tool_ignores_a_residual_walker_phase() {
        assert_eq!(
            background_tool_origin_phase(
                "findings:list",
                Some(crate::app::WorkflowPhase::Hunt),
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
                Some(crate::app::WorkflowPhase::Confirm),
                Some("findings:list"),
            ),
            Some(crate::app::WorkflowPhase::Confirm)
        );
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
