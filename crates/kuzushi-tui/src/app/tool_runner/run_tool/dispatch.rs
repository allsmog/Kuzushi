use super::*;

impl ShellApp {
    pub(crate) fn run_tool(&mut self, tool: Option<String>, input: Option<String>) {
        if self.blocked_by_running_tool() {
            return;
        }
        let Some(request) = self.prepare_run_tool_request(tool, input) else {
            return;
        };
        self.dispatch_run_tool(
            request.tool_name,
            request.input,
            request.workspace,
            request.thinking_level,
        );
    }

    fn prepare_run_tool_request(
        &mut self,
        tool: Option<String>,
        input: Option<String>,
    ) -> Option<RunToolRequest> {
        let Some(tool_name) = self.resolve_run_tool_name(tool) else {
            return None;
        };
        let Some(input) = self.parse_and_prepare_run_input(&tool_name, input) else {
            return None;
        };
        if self.run_launch_deferred(&tool_name, &input) {
            return None;
        }
        let Some(workspace) = self.run_tool_workspace() else {
            return None;
        };
        Some(RunToolRequest {
            thinking_level: thinking_level_from_input(&input)
                .or_else(|| self.session_thinking_level.clone()),
            tool_name,
            input,
            workspace,
        })
    }

    fn run_launch_deferred(&mut self, tool_name: &str, input: &serde_json::Value) -> bool {
        self.blocked_by_pending_threat_review(tool_name)
            || self.request_run_confirmation(tool_name, input)
    }

    fn dispatch_run_tool(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        tool_thinking_level: Option<String>,
    ) {
        let prereqs = prereq_steps_for(&tool_name, workspace.root());
        if !prereqs.is_empty() {
            self.shell_view = ShellView::ModuleRun;
            self.start_prereq_chain(prereqs, tool_name, input, workspace, tool_thinking_level);
            return;
        }
        let status = tool_run_status(&tool_name);
        self.shell_view = ShellView::ModuleRun;
        self.start_background_tool(tool_name, input, workspace, status, tool_thinking_level);
    }

    fn blocked_by_running_tool(&mut self) -> bool {
        let Some(tool_name) = self.tool_running.clone() else {
            return false;
        };
        self.log(
            "tool",
            format!(
                "{tool_name} is still running; wait for its result before starting another tool"
            ),
        );
        self.set_waiting_activity(
            tool_name,
            "another tool was requested while this run is still active",
        );
        true
    }

    fn blocked_by_pending_threat_review(&mut self, tool_name: &str) -> bool {
        if !threat_dependent_tool(tool_name) || self.pending_threat_patch.is_none() {
            return false;
        }
        self.shell_view = ShellView::Threat(ThreatView::Summary);
        self.log(
            "threats",
            format!(
                "{tool_name} needs the current approved threat model; apply or reject the pending threat changes first"
            ),
        );
        self.set_waiting_activity(
            tool_name.to_string(),
            "pending threat-model changes must be approved or rejected before launch",
        );
        true
    }

    fn resolve_run_tool_name(&mut self, tool: Option<String>) -> Option<String> {
        let tool_name = match tool {
            Some(tool) => tool,
            None => self.default_tool_for_run_command().or_else(|| {
                self.log(
                    "error",
                    "run needs a tool, focused module, or loaded sast:scan. Next: modules or run <tool>",
                );
                None
            })?,
        };
        Some(self.resolve_focused_tool_name(tool_name))
    }

    fn parse_and_prepare_run_input(
        &mut self,
        tool_name: &str,
        input: Option<String>,
    ) -> Option<serde_json::Value> {
        let input = self.parse_run_input(input)?;
        match self
            .registry
            .prepare_tool_input(tool_name, input, Some(&self.option_store))
        {
            Ok(input) => Some(input),
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(error.to_string(), "tools, options <tool>, or run <tool> {}"),
                );
                None
            }
        }
    }

    fn parse_run_input(&mut self, input: Option<String>) -> Option<serde_json::Value> {
        let Some(raw) = input.filter(|raw| !raw.trim().is_empty()) else {
            return Some(serde_json::json!({}));
        };
        match serde_json::from_str(&raw) {
            Ok(input) => Some(input),
            Err(error) => {
                self.log(
                    "error",
                    format!("run input must be JSON: {error}. Next: run <tool> {{}}"),
                );
                None
            }
        }
    }

    fn request_run_confirmation(&mut self, tool_name: &str, input: &serde_json::Value) -> bool {
        let Some(request) = confirm_gate_for_tool(tool_name, input, &self.confirm_allowlist) else {
            return false;
        };
        self.log(
            "system",
            format!(
                "{} requires approval — {}",
                tool_name,
                request.kind.label().to_lowercase()
            ),
        );
        self.request_confirm(request);
        true
    }

    fn run_tool_workspace(&mut self) -> Option<WorkspaceTarget> {
        match self.current_workspace() {
            Ok(workspace) => Some(workspace),
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(
                        error.to_string(),
                        "scan <target> or start kuzushi shell --target .",
                    ),
                );
                None
            }
        }
    }
}

fn threat_dependent_tool(tool_name: &str) -> bool {
    matches!(tool_name, "carlini-threat-hunt:run")
}

struct RunToolRequest {
    tool_name: String,
    input: serde_json::Value,
    workspace: WorkspaceTarget,
    thinking_level: Option<String>,
}
