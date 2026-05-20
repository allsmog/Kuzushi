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

    /// Switch to the full-screen transcript view (M1 §1.1). The embedded
    /// 2-row transcript strip only shows the latest lines; this view paints
    /// the entire buffer and is scrollable via `j`/`k`/`g`/`G`/`PgUp`/`PgDn`.
    pub fn show_logs(&mut self) {
        self.shell_view = ShellView::Logs;
        self.scroll_offset = u16::MAX; // start tailing
    }

    /// Reload `.kuzushi/scope.toml` from the active target (M2 §2.1). Called
    /// when the target is set or changed so the footer chip and scope-gated
    /// dispatchers see a fresh allow/deny list. Logs a transcript line on
    /// load errors but does not panic — operators see "scope: load failed".
    pub fn refresh_program_scope(&mut self) {
        let Some(target) = self.target.as_ref() else {
            self.program_scope = None;
            return;
        };
        let workspace = match kuzushi_core::WorkspaceTarget::new(target) {
            Ok(workspace) => workspace,
            Err(_) => {
                self.program_scope = None;
                return;
            }
        };
        match kuzushi_core::load_program_scope(&workspace) {
            Ok(scope) => self.program_scope = scope,
            Err(error) => {
                self.program_scope = None;
                self.log(
                    "error",
                    format!("scope.toml load failed: {error}"),
                );
            }
        }
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
                self.refresh_program_scope();
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
