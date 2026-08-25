use super::*;

impl ShellApp {
    pub(crate) fn reduce_context_command_effects(
        &mut self,
        command: &ContextCommand,
    ) -> Vec<ShellEffect> {
        match command {
            ContextCommand::Show | ContextCommand::Status => vec![ShellEffect::ShowContextStatus],
            ContextCommand::Build => self.reduce_context_build(None),
            ContextCommand::Regen(slice) => self.reduce_context_regen(slice),
        }
    }

    fn reduce_context_regen(&mut self, slice: &str) -> Vec<ShellEffect> {
        match slice {
            "all" | "repo" | "enrichment" | "app-model" => self.reduce_context_build(Some(slice)),
            other => {
                self.log(
                    "error",
                    format!(
                        "unknown context slice {other:?}. Valid slices: all, repo, enrichment, app-model. Next: context regen repo"
                    ),
                );
                Vec::new()
            }
        }
    }

    fn reduce_context_build(&mut self, scope: Option<&str>) -> Vec<ShellEffect> {
        vec![ShellEffect::BuildContext(ContextBuild {
            target: self.target_owned(),
            scope: scope.map(ToString::to_string),
        })]
    }

    pub(crate) fn build_context_effect(&mut self, build: ContextBuild) -> Vec<ShellEffect> {
        let workspace = match workspace_for_target(build.target.as_ref()) {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return Vec::new();
            }
        };
        self.set_target(Some(workspace.root().to_path_buf()));

        let input = match self.prepared_context_build_input(build.scope.as_deref(), &workspace) {
            Ok(input) => input,
            Err(error) => {
                self.log("error", error.to_string());
                return Vec::new();
            }
        };
        self.set_focused_module(Some("context".to_string()));
        self.set_shell_view(ShellView::Context);
        vec![ShellEffect::DispatchRunTool(RunToolLaunch {
            tool_name: "context:build".to_string(),
            input,
            workspace,
            thinking_level: None,
            authorization: ExecutionAuthorization::default(),
        })]
    }

    pub(crate) fn show_context_status(&mut self) {
        match self.refresh_context_view() {
            Ok(()) => {
                self.set_focused_module(Some("context".to_string()));
                self.set_shell_view(ShellView::Context);
                self.log("context", self.domain().context_view().status.clone());
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn prepared_context_build_input(
        &self,
        scope: Option<&str>,
        workspace: &WorkspaceTarget,
    ) -> Result<PreparedToolInput> {
        let ctx = ToolExecutionContext {
            config: self.config(),
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        self.registry().prepare_dispatch_input(
            "context:build",
            context_build_input(scope),
            &ctx,
            Some(self.option_store()),
        )
    }

    pub(crate) fn refresh_context_view(&mut self) -> Result<()> {
        let workspace = self.current_workspace()?;
        let snapshot_path = kuzushi_core::context_snapshot_path(workspace.root());
        self.domain_mut()
            .set_context_view(load_context_snapshot_view(snapshot_path)?);
        Ok(())
    }
}

fn context_build_input(scope: Option<&str>) -> serde_json::Value {
    let mut input = serde_json::Map::new();
    if let Some(scope) = scope {
        input.insert("scope".to_string(), serde_json::json!(scope));
    }
    serde_json::Value::Object(input)
}
