use super::*;

impl ShellApp {
    pub(crate) fn show_context_status(&mut self) {
        match self.refresh_context_view() {
            Ok(()) => {
                self.focused_module = Some("context".to_string());
                self.shell_view = ShellView::Context;
                self.log("context", self.context_view.status.clone());
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    pub(crate) fn build_context_snapshot(&mut self, scope: Option<&str>) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        self.target = Some(workspace.root().to_path_buf());

        let mut input = serde_json::Map::new();
        if let Some(scope) = scope {
            input.insert("scope".to_string(), serde_json::json!(scope));
        }
        let input = match self.registry.prepare_tool_input(
            "context:build",
            serde_json::Value::Object(input),
            Some(&self.option_store),
        ) {
            Ok(input) => input,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        self.focused_module = Some("context".to_string());
        self.shell_view = ShellView::Context;
        self.start_background_tool(
            "context:build".to_string(),
            input,
            workspace,
            "indexing repository context",
            None,
        );
    }

    pub(crate) fn regen_context_slice(&mut self, slice: &str) {
        match slice {
            "all" | "repo" | "app-model" => self.build_context_snapshot(Some(slice)),
            "enrichment" => self.log(
                "error",
                "context regen enrichment is not supported by the native Rust context builder yet. Next: context build",
            ),
            other => self.log(
                "error",
                format!(
                    "unknown context slice {other:?}. Valid slices: all, repo, app-model. Next: context regen repo"
                ),
            ),
        }
    }

    pub(crate) fn refresh_context_view(&mut self) -> Result<()> {
        let workspace = self.current_workspace()?;
        let snapshot_path = workspace.root().join(".kuzushi/context-snapshot.json");
        self.context_view = load_context_snapshot_view(snapshot_path)?;
        Ok(())
    }
}
