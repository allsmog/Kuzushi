use super::*;

impl ShellApp {
    pub(crate) fn reduce_run_tool(
        &mut self,
        tool: Option<String>,
        input: Option<String>,
    ) -> Vec<ShellEffect> {
        let Some(tool_name) = self.resolve_run_tool_name(tool) else {
            return Vec::new();
        };
        vec![ShellEffect::PrepareRunTool(RunToolPreparation {
            tool_name,
            input,
            target: self.target_owned(),
        })]
    }

    pub(crate) fn prepare_run_tool_launch(
        &mut self,
        prepare: RunToolPreparation,
    ) -> Vec<ShellEffect> {
        if self.blocked_by_running_tool() {
            return Vec::new();
        }
        let Some(request) = self.prepare_run_tool_request(prepare) else {
            return Vec::new();
        };
        if self.run_launch_deferred(&request) {
            return Vec::new();
        }
        vec![ShellEffect::DispatchRunTool(request.into_launch())]
    }

    fn prepare_run_tool_request(&mut self, prepare: RunToolPreparation) -> Option<RunToolRequest> {
        let workspace = self.run_tool_workspace(prepare.target.as_ref())?;
        let input =
            self.parse_and_prepare_run_input(&prepare.tool_name, prepare.input, &workspace)?;
        Some(RunToolRequest {
            thinking_level: thinking_level_from_input(&input)
                .or_else(|| self.session_thinking_level_owned()),
            tool_name: prepare.tool_name,
            input,
            workspace,
        })
    }

    fn run_launch_deferred(&mut self, request: &RunToolRequest) -> bool {
        self.blocked_by_pending_threat_review(&request.tool_name)
            || self.request_run_confirmation(request)
    }

    pub(crate) fn dispatch_run_tool(
        &mut self,
        tool_name: String,
        input: serde_json::Value,
        workspace: WorkspaceTarget,
        tool_thinking_level: Option<String>,
    ) -> Vec<ShellEffect> {
        let prereqs = prereq_steps_for(&tool_name, workspace.root());
        if !prereqs.is_empty() {
            self.set_shell_view(ShellView::ModuleRun);
            return self.start_prereq_chain(
                prereqs,
                tool_name,
                input,
                workspace,
                tool_thinking_level,
            );
        }
        let status = tool_run_status(&tool_name);
        self.set_shell_view(ShellView::ModuleRun);
        self.start_background_tool(tool_name, input, workspace, status, tool_thinking_level);
        Vec::new()
    }

    fn blocked_by_running_tool(&mut self) -> bool {
        let Some(tool_name) = self.running_tool_name_owned() else {
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
        if !threat_dependent_tool(tool_name) || !self.engagement.has_pending_threat_patch() {
            return false;
        }
        self.router.threat_mut().open(ThreatView::Summary);
        self.set_shell_view(ShellView::Threat);
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
        workspace: &WorkspaceTarget,
    ) -> Option<serde_json::Value> {
        let input = self.parse_run_input_for_tool(tool_name, input)?;
        let ctx = ToolExecutionContext {
            config: self.config(),
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
        };
        match self.registry().prepare_tool_input_for_dispatch(
            tool_name,
            input,
            &ctx,
            Some(self.option_store()),
        ) {
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

    fn parse_run_input_for_tool(
        &mut self,
        tool_name: &str,
        input: Option<String>,
    ) -> Option<serde_json::Value> {
        match input {
            Some(raw) if !raw.trim().is_empty() => self.parse_run_input(Some(raw)),
            _ => Some(self.default_run_input_for_tool(tool_name)),
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

    fn default_run_input_for_tool(&self, tool_name: &str) -> serde_json::Value {
        if tool_name == "patch:finding" {
            if let Some((_, finding)) = crate::ui_view_models::current_finding_for_detail(self) {
                return serde_json::json!({ "fingerprint": finding.fingerprint });
            }
        }
        serde_json::json!({})
    }

    fn request_run_confirmation(&mut self, request: &RunToolRequest) -> bool {
        let Some(confirm) = confirm_gate_for_tool(
            &request.tool_name,
            &request.input,
            self.engagement.confirm_allowlist(),
        ) else {
            return false;
        };
        self.log(
            "system",
            format!(
                "{} requires approval — {}",
                confirm.tool,
                confirm.kind.label().to_lowercase()
            ),
        );
        self.request_confirm_for_run(confirm, request.clone().into_launch());
        true
    }

    fn run_tool_workspace(&mut self, target: Option<&PathBuf>) -> Option<WorkspaceTarget> {
        match workspace_for_target(target) {
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
    matches!(
        tool_name,
        "carlini-threat-hunt:run" | "offense-review:threat-hunt"
    )
}

#[derive(Clone)]
struct RunToolRequest {
    tool_name: String,
    input: serde_json::Value,
    workspace: WorkspaceTarget,
    thinking_level: Option<String>,
}

impl RunToolRequest {
    fn into_launch(self) -> RunToolLaunch {
        RunToolLaunch {
            tool_name: self.tool_name,
            input: self.input,
            workspace: self.workspace,
            thinking_level: self.thinking_level,
        }
    }
}
