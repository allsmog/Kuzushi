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
        if self.tool_launch_blocked(&prepare.tool_name) {
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
            thinking_level: thinking_level_from_input(input.value())
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
        input: PreparedToolInput,
        workspace: WorkspaceTarget,
        tool_thinking_level: Option<String>,
        authorization: ExecutionAuthorization,
    ) -> Vec<ShellEffect> {
        if self.tool_launch_blocked(&tool_name) {
            return Vec::new();
        }
        let prereqs = prereq_steps_for(&tool_name, workspace.root());
        if !prereqs.is_empty() {
            return self.start_prepared_prereq_chain(
                prereqs,
                tool_name,
                input,
                workspace,
                tool_thinking_level,
                authorization,
            );
        }
        let status = tool_run_status(&tool_name);
        self.start_authorized_prepared_background_tool(
            tool_name,
            input,
            workspace,
            status,
            tool_thinking_level,
            authorization,
        );
        Vec::new()
    }

    pub(crate) fn tool_launch_blocked(&mut self, requested_tool: &str) -> bool {
        if !self.has_running_work() {
            return false;
        }
        if let Some(active_tool) = self.running_tool_name_owned() {
            self.log(
                "tool",
                format!(
                    "{active_tool} is still running; wait for its result before starting {requested_tool}"
                ),
            );
            self.set_waiting_activity(
                active_tool,
                "another tool was requested while this run is still active",
            );
            return true;
        }
        self.log(
            "tool",
            format!(
                "{requested_tool} launch blocked — finish or cancel the active work, then retry"
            ),
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
    ) -> Option<PreparedToolInput> {
        let input = self.parse_run_input_for_tool(tool_name, input)?;
        let ctx = ToolExecutionContext {
            config: self.config(),
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        match self.registry().prepare_dispatch_input(
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
        let input_gate = confirm_gate_for_tool(
            &request.tool_name,
            request.input.value(),
            self.engagement.confirm_allowlist(),
        );
        let descriptor_gate = || {
            self.registry()
                .resolve_tool(&request.tool_name)
                .and_then(|descriptor| {
                    descriptor_approval_confirm(descriptor, request.input.value())
                })
                .map(|confirm| patch_validation_confirm(confirm, request))
        };
        let Some(confirm) = input_gate.or_else(descriptor_gate) else {
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
        match initialized_run_workspace(target) {
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

fn initialized_run_workspace(target: Option<&PathBuf>) -> anyhow::Result<WorkspaceTarget> {
    let workspace = workspace_for_target(target)?;
    workspace.ensure_state_dir()?;
    Ok(workspace)
}

fn patch_validation_confirm(
    mut confirm: PendingConfirm,
    request: &RunToolRequest,
) -> PendingConfirm {
    let delegates_patch = request.tool_name == "patch:finding"
        || (request.tool_name == "sast:scan"
            && request
                .input
                .value()
                .get("autoPatch")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false));
    if !delegates_patch {
        return confirm;
    }
    confirm.target = request.workspace.root().display().to_string();
    confirm.rationale = Some(
        kuzushi_core::patch::patch_validation_disclosure(
            request.workspace.root(),
            request.input.value(),
        )
        .unwrap_or_else(|error| format!("validation command disclosure failed: {error}")),
    );
    confirm
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
    input: PreparedToolInput,
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
            authorization: ExecutionAuthorization::default(),
        }
    }
}

#[cfg(test)]
mod workspace_initialization_tests {
    use super::*;

    #[test]
    fn run_workspace_initializes_policy_before_request_state() {
        let target = tempfile::tempdir().unwrap();
        let target_path = target.path().to_path_buf();

        let workspace = initialized_run_workspace(Some(&target_path)).unwrap();

        assert!(workspace.root().join(".kuzushi/.gitignore").is_file());
        assert!(workspace.state_dir().is_dir());
    }
}
