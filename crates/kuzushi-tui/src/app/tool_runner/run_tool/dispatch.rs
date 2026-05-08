use super::*;

impl ShellApp {
    pub(crate) fn run_tool(&mut self, tool: Option<String>, input: Option<String>) {
        if self.blocked_by_running_tool() {
            return;
        }

        let Some(tool_name) = self.resolve_run_tool_name(tool) else {
            return;
        };
        let Some(input) = self.parse_and_prepare_run_input(&tool_name, input) else {
            return;
        };
        if self.request_run_confirmation(&tool_name, &input) {
            return;
        }
        let Some(workspace) = self.run_tool_workspace() else {
            return;
        };
        let tool_thinking_level =
            thinking_level_from_input(&input).or_else(|| self.session_thinking_level.clone());
        self.dispatch_run_tool(tool_name, input, workspace, tool_thinking_level);
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
        let Some(tool_name) = self.tool_running.as_deref() else {
            return false;
        };
        self.log(
            "tool",
            format!(
                "{tool_name} is still running; wait for its result before starting another tool"
            ),
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
