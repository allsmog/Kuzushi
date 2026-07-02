use super::*;
use std::path::Path;

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
                self.log("error", format!("scope.toml load failed: {error}"));
            }
        }
    }

    pub fn handle_target_command(&mut self, raw: Option<&str>) {
        let Some(raw) = target_argument(raw) else {
            self.log_current_target();
            return;
        };
        let path = PathBuf::from(raw);
        match WorkspaceTarget::new(&path) {
            Ok(workspace) => self.activate_target(workspace),
            Err(error) => self.log("error", format!("invalid target {raw:?}: {error}")),
        }
    }

    fn log_current_target(&mut self) {
        let current = self
            .target
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<unset>".to_string());
        self.log("target", format!("current target: {current}"));
    }

    pub(crate) fn activate_target(&mut self, workspace: WorkspaceTarget) {
        let root = workspace.root().to_path_buf();
        self.target = Some(root.clone());
        if self.ensure_target_state_dir(&workspace, &root) {
            self.record_active_target(&root);
            self.refresh_active_scope_tree(&root);
        }
        self.refresh_findings(false);
        self.refresh_program_scope();
    }

    fn ensure_target_state_dir(&mut self, workspace: &WorkspaceTarget, root: &Path) -> bool {
        match workspace.ensure_state_dir() {
            Ok(_) => {
                self.log("target", format!("set {}", root.display()));
                true
            }
            Err(error) => {
                self.log(
                    "target",
                    format!("set {} but state dir init failed: {error}", root.display()),
                );
                false
            }
        }
    }

    fn record_active_target(&mut self, root: &Path) {
        if let Err(error) = crate::app::record_recent_target(root) {
            self.log("target", format!("target history not updated: {error}"));
        }
    }

    fn refresh_active_scope_tree(&mut self, root: &Path) {
        if let Some(tree) = self.refresh_nested_project_scopes(root) {
            self.active_scope = active_scope_from_tree(&tree, None);
        }
    }

    pub fn handle_target_revision_command(&mut self, reference: &str) {
        let Some(target) = self.target.clone() else {
            self.log(
                "target",
                "revision switch requires an active target; run target <path> first",
            );
            return;
        };
        match kuzushi_core::switch_target_revision(&target, reference) {
            Ok(outcome) => {
                *self.workbench_cache.borrow_mut() = WorkbenchCache::default();
                let preferred_scope = self.active_scope.as_ref().map(|scope| scope.id.clone());
                if let Some(tree) = self.refresh_nested_project_scopes(&target) {
                    self.active_scope = active_scope_from_tree(&tree, preferred_scope.as_deref());
                }
                self.refresh_findings(false);
                self.refresh_program_scope();
                self.log(
                    "target",
                    format!(
                        "switched revision {} -> {}",
                        short_revision(&outcome.previous.sha),
                        short_revision(&outcome.current.sha)
                    ),
                );
            }
            Err(error) => self.log(
                "target",
                format!("revision switch blocked for {reference:?}: {error}"),
            ),
        }
    }

    pub(crate) fn apply_component_selection(&mut self, raw: Option<&str>) {
        let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
            self.log(
                "component",
                "select a component path or id; use `recommend` to inspect candidates",
            );
            self.open_workbench(crate::app::WorkbenchPane::Findings);
            return;
        };
        if matches!(raw, "all" | "clear" | "root" | ".") {
            self.active_scope = None;
            self.findings_cursor = 0;
            self.open_workbench(crate::app::WorkbenchPane::Findings);
            self.log("component", "cleared component filter");
            return;
        }
        let Some(scope) = self.find_component_scope(raw) else {
            self.log(
                "component",
                format!("no component matches {raw:?}; run `recommend` or `project`"),
            );
            self.open_workbench(crate::app::WorkbenchPane::Findings);
            return;
        };
        self.active_scope = Some(scope.clone());
        self.findings_cursor = 0;
        self.open_workbench(crate::app::WorkbenchPane::Findings);
        self.log(
            "component",
            format!(
                "showing findings under {} ({})",
                scope.rel_path,
                scope.kind.label()
            ),
        );
    }

    fn find_component_scope(&mut self, raw: &str) -> Option<TargetCandidateScope> {
        let target = self.target.clone()?;
        let state = self
            .workbench_cache
            .borrow_mut()
            .project_scope_tree(Some(target.as_path()))?;
        component_scope_from_state(&state, raw)
    }

    fn refresh_nested_project_scopes(
        &mut self,
        root: &std::path::Path,
    ) -> Option<kuzushi_core::NestedProjectScopeTree> {
        match kuzushi_core::discover_and_save_nested_project_scopes(root) {
            Ok(tree) => {
                let nested_count = tree.scopes.len().saturating_sub(1);
                if nested_count > 0 {
                    self.log(
                        "target",
                        format!("project scopes refreshed: {nested_count} nested scope(s)"),
                    );
                }
                Some(tree)
            }
            Err(error) => {
                self.log("target", format!("project scope discovery failed: {error}"));
                None
            }
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

fn target_argument(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|raw| !raw.is_empty())
}

fn short_revision(sha: &str) -> String {
    sha.chars().take(7).collect()
}

fn active_scope_from_tree(
    tree: &kuzushi_core::NestedProjectScopeTree,
    preferred_id: Option<&str>,
) -> Option<TargetCandidateScope> {
    preferred_id
        .and_then(|id| tree.scopes.iter().find(|scope| scope.id == id))
        .or_else(|| tree.root_scope())
        .map(TargetCandidateScope::from)
}

fn component_scope_from_state(
    state: &ProjectScopeTreeState,
    raw: &str,
) -> Option<TargetCandidateScope> {
    let tree = match state {
        ProjectScopeTreeState::Persisted(tree) | ProjectScopeTreeState::Discovered(tree) => tree,
        ProjectScopeTreeState::RootOnly | ProjectScopeTreeState::Unreadable(_) => return None,
    };
    let raw_path = raw.trim_end_matches('/');
    tree.non_root_scopes()
        .find(|scope| {
            component_scope_kind(scope.kind)
                && (scope.id == raw
                    || scope.rel_path == raw
                    || scope.display_label() == raw
                    || scope.rel_path.trim_end_matches('/') == raw_path)
        })
        .map(TargetCandidateScope::from)
}

fn component_scope_kind(kind: kuzushi_core::NestedProjectKind) -> bool {
    matches!(
        kind,
        kuzushi_core::NestedProjectKind::Submodule
            | kuzushi_core::NestedProjectKind::PackageRoot
            | kuzushi_core::NestedProjectKind::EntrypointCluster
    )
}
