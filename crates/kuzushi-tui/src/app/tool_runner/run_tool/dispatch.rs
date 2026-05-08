use super::*;

impl ShellApp {
    pub(crate) fn run_tool(&mut self, tool: Option<String>, input: Option<String>) {
        if let Some(tool_name) = self.tool_running.as_deref() {
            self.log(
                "tool",
                format!("{tool_name} is still running; wait for its result before starting another tool"),
            );
            return;
        }

        let tool_name = match tool {
            Some(tool) => tool,
            None => match self.default_tool_for_run_command() {
                Some(tool) => tool,
                None => {
                    self.log(
                        "error",
                        "run needs a tool, focused module, or loaded sast:scan. Next: modules or run <tool>",
                    );
                    return;
                }
            },
        };
        let tool_name = self.resolve_focused_tool_name(tool_name);

        let input = match input {
            Some(raw) if !raw.trim().is_empty() => match serde_json::from_str(&raw) {
                Ok(input) => input,
                Err(error) => {
                    self.log(
                        "error",
                        format!("run input must be JSON: {error}. Next: run <tool> {{}}"),
                    );
                    return;
                }
            },
            _ => serde_json::json!({}),
        };
        let input =
            match self
                .registry
                .prepare_tool_input(&tool_name, input, Some(&self.option_store))
            {
                Ok(input) => input,
                Err(error) => {
                    self.log(
                        "error",
                        with_next_step(
                            error.to_string(),
                            "tools, options <tool>, or run <tool> {}",
                        ),
                    );
                    return;
                }
            };

        // Confirm gate preflight (`design/mockups/confirm-dialog.jsx`).
        // If the tool + input matches a known-risky shape (network
        // egress, fs:write outside `.kuzushi/`, destructive verb),
        // surface a `PendingConfirm` and pause the dispatch.  The
        // operator resolves with y/Y/n/N; on `y`/`Y` they re-run the
        // command and the gate doesn't fire again because `remembered`
        // adds the target to the session allowlist.
        if let Some(request) = confirm_gate_for_tool(&tool_name, &input, &self.confirm_allowlist) {
            self.log(
                "system",
                format!(
                    "{} requires approval — {}",
                    tool_name,
                    request.kind.label().to_lowercase()
                ),
            );
            self.request_confirm(request);
            return;
        }

        let workspace = match self.current_workspace() {
            Ok(workspace) => Some(workspace),
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(
                        error.to_string(),
                        "scan <target> or start kuzushi shell --target .",
                    ),
                );
                return;
            }
        };
        let tool_thinking_level =
            thinking_level_from_input(&input).or_else(|| self.session_thinking_level.clone());
        let status = tool_run_status(&tool_name);
        self.shell_view = ShellView::ModuleRun;
        self.start_background_tool(
            tool_name,
            input,
            workspace.expect("current_workspace returned Some workspace"),
            status,
            tool_thinking_level,
        );
    }
}
