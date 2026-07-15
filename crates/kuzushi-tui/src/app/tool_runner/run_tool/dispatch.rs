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
        let input = force_shell_discovery_only_sast_input(tool_name, input);
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
        let Some(confirm) = self.run_confirmation(request) else {
            return false;
        };
        self.apply_run_confirmation(confirm, request)
    }

    fn run_confirmation(&self, request: &RunToolRequest) -> Option<PendingConfirm> {
        let empty_allowlist = std::collections::BTreeSet::new();
        let input_gate =
            confirm_gate_for_tool(&request.tool_name, request.input.value(), &empty_allowlist);
        input_gate.or_else(|| {
            self.registry()
                .resolve_tool(&request.tool_name)
                .and_then(|descriptor| {
                    descriptor_approval_confirm(descriptor, request.input.value())
                })
                .map(|confirm| patch_validation_confirm(confirm, request))
        })
    }

    fn apply_run_confirmation(
        &mut self,
        confirm: PendingConfirm,
        request: &RunToolRequest,
    ) -> bool {
        match remembered_confirm_decision(
            &confirm,
            self.engagement.confirm_allowlist(),
            self.engagement.confirm_denylist(),
        ) {
            RememberedConfirmDecision::Allow => false,
            RememberedConfirmDecision::Deny => {
                self.block_remembered_confirmation(&confirm);
                true
            }
            RememberedConfirmDecision::Ask => {
                self.prompt_run_confirmation(confirm, request);
                true
            }
        }
    }

    fn prompt_run_confirmation(&mut self, confirm: PendingConfirm, request: &RunToolRequest) {
        self.log(
            "system",
            format!(
                "{} requires approval — {}",
                confirm.tool,
                confirm.kind.label().to_lowercase()
            ),
        );
        self.request_confirm_for_run(confirm, request.clone().into_launch());
    }

    fn block_remembered_confirmation(&mut self, confirm: &PendingConfirm) {
        self.set_warn_notice(
            "approval",
            format!(
                "{} {} blocked by remembered denial for this session; change the exact target or restart Kuzushi to reconsider",
                confirm.tool, confirm.target
            ),
        );
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

#[cfg(test)]
mod remembered_confirmation_tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use kuzushi_core::V2Config;

    fn prepare(
        app: &mut ShellApp,
        workspace: &WorkspaceTarget,
        tool_name: &str,
        input: serde_json::Value,
    ) -> Vec<ShellEffect> {
        app.prepare_run_tool_launch(RunToolPreparation {
            tool_name: tool_name.to_string(),
            input: Some(input.to_string()),
            target: Some(workspace.root().to_path_buf()),
        })
    }

    fn remember_key(ch: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(ch), KeyModifiers::SHIFT)
    }

    fn pwn_input(target: &str) -> serde_json::Value {
        serde_json::json!({"target": target, "stateId": "state-1"})
    }

    #[test]
    fn remembered_descriptor_denial_blocks_exact_scope_without_run_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("source.txt"), "unchanged").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        let input = serde_json::json!({"target": "127.0.0.1"});

        assert!(prepare(&mut app, &workspace, "recon:nmap", input.clone()).is_empty());
        assert!(app.reduce_key(remember_key('N')).effects.is_empty());
        assert!(prepare(&mut app, &workspace, "recon:nmap", input).is_empty());

        assert!(app.advisory().pending_confirm.is_none());
        assert!(app.advisory().pending_confirm_launch.is_none());
        let notice = app.advisory().notice.as_ref().expect("visible denial");
        assert_eq!(notice.severity, NoticeSeverity::Warn);
        assert!(notice.message.contains("recon:nmap 127.0.0.1 blocked"));
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("source.txt")).unwrap(),
            "unchanged"
        );
        assert!(!kuzushi_core::runs_root(workspace.root()).exists());
    }

    #[test]
    fn remembered_descriptor_denial_does_not_match_another_target() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        assert!(prepare(
            &mut app,
            &workspace,
            "recon:nmap",
            serde_json::json!({"target": "127.0.0.1"}),
        )
        .is_empty());
        app.reduce_key(remember_key('N'));
        assert!(prepare(
            &mut app,
            &workspace,
            "recon:nmap",
            serde_json::json!({"target": "127.0.0.2"}),
        )
        .is_empty());

        let confirm = app
            .advisory()
            .pending_confirm
            .as_ref()
            .expect("new scope prompt");
        assert_eq!(confirm.target, "127.0.0.2");
    }

    #[test]
    fn remembered_input_denial_blocks_same_candidate_request() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        let input = pwn_input("127.0.0.1:31337");

        assert!(prepare(&mut app, &workspace, "pwn:run-candidates", input.clone()).is_empty());
        app.reduce_key(remember_key('N'));
        assert!(prepare(&mut app, &workspace, "pwn:run-candidates", input).is_empty());

        assert!(app.advisory().pending_confirm.is_none());
        assert!(app.advisory().pending_confirm_launch.is_none());
        assert!(app
            .advisory()
            .notice
            .as_ref()
            .is_some_and(|notice| notice.message.contains("remembered denial")));
    }

    #[test]
    fn remembered_input_allow_skips_the_same_candidate_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        let input = pwn_input("127.0.0.1:31337");

        assert!(prepare(&mut app, &workspace, "pwn:run-candidates", input.clone()).is_empty());
        let approved = app.reduce_key(remember_key('Y'));
        assert!(matches!(
            approved.effects.as_slice(),
            [ShellEffect::DispatchRunTool(_)]
        ));

        let repeated = prepare(&mut app, &workspace, "pwn:run-candidates", input);
        assert!(matches!(
            repeated.as_slice(),
            [ShellEffect::DispatchRunTool(_)]
        ));
        assert!(app.advisory().pending_confirm.is_none());
    }

    #[test]
    fn descriptor_shift_y_cannot_resolve_or_launch_but_lowercase_y_can() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        assert!(prepare(
            &mut app,
            &workspace,
            "recon:nmap",
            serde_json::json!({"target": "127.0.0.1"}),
        )
        .is_empty());
        let remembered = app.reduce_key(remember_key('Y'));
        assert!(remembered.effects.is_empty());
        assert!(app.advisory().pending_confirm.is_some());
        assert!(app.advisory().pending_confirm_launch.is_some());

        let once = app.reduce_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert!(matches!(
            once.effects.as_slice(),
            [ShellEffect::DispatchRunTool(_)]
        ));
        assert!(app.engagement.confirm_allowlist().is_empty());
    }
}
