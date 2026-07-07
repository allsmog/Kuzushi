use self::dispatch::{
    prepare_background_tool_dispatch, BackgroundToolDispatch, BackgroundToolRun,
    BackgroundToolWorkerLaunch,
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
        self.start_background_tool_with_activity(
            tool_name,
            input,
            workspace,
            status,
            thinking_level,
            None,
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
        if self.reject_background_tool_overlap(&tool_name) {
            return;
        }
        if self.reject_pending_prompt_mutation(&workspace, &tool_name) {
            return;
        }
        if let Some(error) = self.langgraph_background_tool_launch_blocker(&tool_name, &input) {
            self.log("error", error);
            return;
        }

        let ticket = self.jobs_mut().start(JobKind::Run, tool_name.clone());
        let dispatch = self.background_tool_dispatch(&workspace, &tool_name, &input, ticket);
        self.launch_prepared_background_tool(
            dispatch,
            workspace,
            tool_name,
            input,
            thinking_level,
            status,
            activity,
        );
        self.open_activity_for_started_background_tool();
    }

    fn background_tool_dispatch(
        &self,
        workspace: &WorkspaceTarget,
        tool_name: &str,
        input: &serde_json::Value,
        ticket: JobTicket,
    ) -> BackgroundToolDispatch {
        prepare_background_tool_dispatch(
            self.registry(),
            self.config(),
            workspace,
            tool_name,
            input,
            ticket,
            self.jobs().trace_budget(),
        )
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
    ) {
        let model_override = active_model_override_from_input(&input, &dispatch.config);
        BackgroundToolWorkerLaunch::from_dispatch(
            dispatch,
            workspace,
            tool_name,
            input,
            thinking_level,
        )
        .attach_and_start(self, status, activity, model_override);
    }

    fn reject_background_tool_overlap(&mut self, tool_name: &str) -> bool {
        let Some(active) = self.running_tool_name() else {
            return false;
        };
        self.log(
            "tool",
            format!("{active} is still running; wait for its result before starting {tool_name}"),
        );
        true
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
        if !self.registry().tool_needs_runtime(tool_name, input) {
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
        self.set_activity(Some(ActivitySession::new(run.run_id.clone())));
        self.start_tool_run(
            tool_name.to_string(),
            cancel,
            run.run_id.clone(),
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
