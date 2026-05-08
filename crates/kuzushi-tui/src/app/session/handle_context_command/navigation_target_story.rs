use super::*;

impl ShellApp {
    pub fn show_quickstart(&mut self) {
        self.shell_view = ShellView::Quickstart;
        // Two log lines (not eight) for the operator-facing transcript.
        // The full guide is rendered in the Quickstart view, which gets the
        // full body area instead of the 2-row transcript strip.
        let scan_command = self.first_finding_scan_command();
        self.log(
            "quickstart",
            format!("Exact first-finding path: {scan_command} -> findings"),
        );
    }

    pub fn handle_target_command(&mut self, raw: Option<&str>) {
        let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
            let current = self
                .target
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<unset>".to_string());
            self.log("target", format!("current target: {current}"));
            return;
        };
        let path = PathBuf::from(raw);
        match WorkspaceTarget::new(&path) {
            Ok(workspace) => {
                let root = workspace.root().to_path_buf();
                self.target = Some(root.clone());
                if let Err(error) = workspace.ensure_state_dir() {
                    self.log(
                        "target",
                        format!("set {} but state dir init failed: {error}", root.display()),
                    );
                } else {
                    self.log("target", format!("set {}", root.display()));
                }
                self.refresh_findings(false);
            }
            Err(error) => self.log("error", format!("invalid target {raw:?}: {error}")),
        }
    }

    pub(crate) fn show_story(&mut self) {
        if matches!(self.shell_view, ShellView::Story) {
            return;
        }
        self.story_return_view = Some(self.shell_view.clone());
        self.shell_view = ShellView::Story;
    }

    pub fn toggle_story_overlay(&mut self) {
        if matches!(self.shell_view, ShellView::Story) {
            if let Some(previous) = self.story_return_view.take() {
                self.shell_view = previous;
            } else {
                self.shell_view = ShellView::Catalog;
            }
        } else {
            self.show_story();
        }
    }
}
