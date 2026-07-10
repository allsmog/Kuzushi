use super::*;
use std::path::Path;

impl ShellApp {
    pub fn show_quickstart(&mut self) {
        self.set_shell_view(ShellView::Quickstart);
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
        self.set_shell_view(ShellView::Logs);
        self.router.logs_mut().set_scroll(usize::MAX); // start tailing
    }

    /// Reload `.kuzushi/scope.toml` from the active target (M2 §2.1). Called
    /// when the target is set or changed so the footer chip and scope-gated
    /// dispatchers see a fresh allow/deny list. Logs a transcript line on
    /// load errors but does not panic — operators see "scope: load failed".
    pub fn refresh_program_scope(&mut self) {
        let Some(target) = self.target_path_buf() else {
            self.domain_mut().set_program_scope(None);
            return;
        };
        let workspace = match kuzushi_core::WorkspaceTarget::new(target) {
            Ok(workspace) => workspace,
            Err(_) => {
                self.domain_mut().set_program_scope(None);
                return;
            }
        };
        match kuzushi_core::load_program_scope(&workspace) {
            Ok(scope) => self.domain_mut().set_program_scope(scope),
            Err(error) => {
                self.domain_mut().set_program_scope(None);
                self.log("error", format!("scope.toml load failed: {error}"));
            }
        }
    }

    pub(crate) fn reduce_target_command(&mut self, raw: Option<&str>) -> Vec<ShellEffect> {
        let Some(raw) = target_argument(raw) else {
            self.log_current_target();
            return Vec::new();
        };
        vec![ShellEffect::ActivateTarget(TargetActivation {
            path: PathBuf::from(raw),
            selected_scope: None,
            source: TargetActivationSource::Command,
        })]
    }

    pub(crate) fn activate_target_effect(
        &mut self,
        activation: TargetActivation,
    ) -> Vec<ShellEffect> {
        let label = activation.path.display().to_string();
        match WorkspaceTarget::new(&activation.path) {
            Ok(workspace) => {
                let effects = self.activate_target(workspace);
                self.apply_initial_onboarding_phase();
                self.finish_target_activation(activation);
                effects
            }
            Err(error) => {
                self.log("error", format!("invalid target {label:?}: {error}"));
                Vec::new()
            }
        }
    }

    fn log_current_target(&mut self) {
        let current = self
            .target()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<unset>".to_string());
        self.log("target", format!("current target: {current}"));
    }

    pub(crate) fn activate_target(&mut self, workspace: WorkspaceTarget) -> Vec<ShellEffect> {
        let root = workspace.root().to_path_buf();
        self.set_target(Some(root.clone()));
        if self.ensure_target_state_dir(&workspace, &root) {
            self.record_active_target(&root);
            self.refresh_active_scope_tree(&root);
        }
        self.apply_ready_default_model_after_target_activation();
        vec![
            ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None,
            }),
            ShellEffect::RefreshProgramScope,
        ]
    }

    fn finish_target_activation(&mut self, activation: TargetActivation) {
        if let Some(scope) = activation.selected_scope {
            self.set_active_scope(Some(scope.clone()));
            self.log(
                "target",
                format!(
                    "entered {} scope {} ({})",
                    scope.kind.label(),
                    scope.rel_path,
                    scope.id
                ),
            );
        }
        if activation.source == TargetActivationSource::Picker
            && self.shell_view() == ShellView::TargetPicker
        {
            self.set_shell_view(ShellView::Workbench);
            self.router
                .workbench_mut()
                .set_focus(WorkbenchPane::Findings);
            let center_mode = self.default_workbench_center_mode(WorkbenchPane::Findings);
            self.router.workbench_mut().set_center_mode(center_mode);
            self.clamp_findings_cursor();
        }
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
        match kuzushi_core::load_nested_project_scopes(root) {
            Ok(Some(tree)) => {
                self.workbench_cache()
                    .borrow_mut()
                    .cache_persisted_project_scope_tree(root, tree.clone());
                self.set_active_scope(active_scope_from_tree(&tree, None));
            }
            Ok(None) => self.set_active_scope(Some(root_target_scope())),
            Err(error) => {
                self.set_active_scope(Some(root_target_scope()));
                self.log(
                    "scope:mapping",
                    format!("persisted project scopes unavailable; using root: {error}"),
                );
            }
        }
        self.runtime_state
            .start_project_scope_discovery(root.to_path_buf());
    }

    pub(crate) fn reduce_target_revision_command(&mut self, reference: &str) -> Vec<ShellEffect> {
        let Some(target) = self.target_owned() else {
            self.log(
                "target",
                "revision switch requires an active target; run target <path> first",
            );
            return Vec::new();
        };
        vec![ShellEffect::SwitchTargetRevision(TargetRevisionSwitch {
            target,
            reference: reference.to_string(),
        })]
    }

    pub(crate) fn switch_target_revision_effect(
        &mut self,
        switch: TargetRevisionSwitch,
    ) -> Vec<ShellEffect> {
        match kuzushi_core::switch_target_revision(&switch.target, &switch.reference) {
            Ok(outcome) => self.apply_target_revision_switch(
                &switch.target,
                &outcome.previous.sha,
                &outcome.current.sha,
            ),
            Err(error) => {
                self.log_target_revision_switch_error(&switch.reference, error);
                Vec::new()
            }
        }
    }

    fn apply_target_revision_switch(
        &mut self,
        target: &Path,
        previous_sha: &str,
        current_sha: &str,
    ) -> Vec<ShellEffect> {
        *self.workbench_cache().borrow_mut() = WorkbenchCache::default();
        self.refresh_target_scope_after_revision_switch(target);
        self.log_target_revision_switch(previous_sha, current_sha);
        target_revision_refresh_effects()
    }

    fn refresh_target_scope_after_revision_switch(&mut self, target: &Path) {
        self.refresh_active_scope_tree(target);
    }

    fn log_target_revision_switch(&mut self, previous_sha: &str, current_sha: &str) {
        self.log(
            "target",
            format!(
                "switched revision {} -> {}",
                short_revision(previous_sha),
                short_revision(current_sha)
            ),
        );
    }

    fn log_target_revision_switch_error(&mut self, reference: &str, error: anyhow::Error) {
        self.log(
            "target",
            format!("revision switch blocked for {reference:?}: {error}"),
        );
    }

    pub(crate) fn reduce_component_selection(&self, raw: Option<&str>) -> Vec<ShellEffect> {
        vec![ShellEffect::SelectComponent(ComponentSelection {
            target: self.target_owned(),
            raw: raw.map(ToString::to_string),
        })]
    }

    pub(crate) fn select_component_effect(
        &mut self,
        selection: ComponentSelection,
    ) -> Vec<ShellEffect> {
        let target = selection.target;
        let raw = selection.raw.as_deref();
        let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
            self.log(
                "component",
                "select a component path or id; use `recommend` to inspect candidates",
            );
            return self.open_workbench_effects(crate::app::WorkbenchPane::Findings);
        };
        if matches!(raw, "all" | "clear" | "root" | ".") {
            self.set_active_scope(None);
            self.router.findings_mut().reset();
            self.log("component", "cleared component filter");
            return self.open_workbench_effects(crate::app::WorkbenchPane::Findings);
        }
        let Some(scope) = self.find_component_scope(target.as_deref(), raw) else {
            self.log(
                "component",
                format!("no component matches {raw:?}; run `recommend` or `project`"),
            );
            return self.open_workbench_effects(crate::app::WorkbenchPane::Findings);
        };
        self.set_active_scope(Some(scope.clone()));
        self.router.findings_mut().reset();
        self.log(
            "component",
            format!(
                "showing findings under {} ({})",
                scope.rel_path,
                scope.kind.label()
            ),
        );
        self.open_workbench_effects(crate::app::WorkbenchPane::Findings)
    }

    fn find_component_scope(
        &mut self,
        target: Option<&std::path::Path>,
        raw: &str,
    ) -> Option<TargetCandidateScope> {
        let target = target?;
        let state = self
            .workbench_cache()
            .borrow_mut()
            .project_scope_tree(Some(target))?;
        component_scope_from_state(&state, raw)
    }

    pub(crate) fn apply_project_scope_discovery_results(&mut self) -> bool {
        let results = self.runtime_state.drain_project_scope_discovery();
        let changed = !results.is_empty();
        for result in results {
            self.apply_project_scope_discovery_result(result);
        }
        changed
    }

    fn apply_project_scope_discovery_result(&mut self, result: ProjectScopeDiscoveryResult) {
        match result.tree {
            Ok(tree) => self.apply_discovered_project_scopes(&result.root, tree),
            Err(error) => self.log(
                "scope:mapping",
                format!("project scope discovery failed; root remains usable: {error}"),
            ),
        }
    }

    fn apply_discovered_project_scopes(
        &mut self,
        root: &Path,
        tree: kuzushi_core::NestedProjectScopeTree,
    ) {
        let preferred = self.active_scope().map(|scope| scope.id.clone());
        self.workbench_cache()
            .borrow_mut()
            .cache_persisted_project_scope_tree(root, tree.clone());
        self.set_active_scope(active_scope_from_tree(&tree, preferred.as_deref()));
        self.log(
            "scope:mapping",
            format!(
                "project scopes ready: {} nested scope(s)",
                tree.scopes.len().saturating_sub(1)
            ),
        );
    }

    pub(crate) fn show_story(&mut self) {
        if matches!(self.shell_view(), ShellView::Story) {
            return;
        }
        let origin = self.shell_view();
        self.router.navigation_mut().push_overlay_origin(origin);
        self.set_shell_view(ShellView::Story);
    }

    pub fn toggle_story_overlay(&mut self) {
        if matches!(self.shell_view(), ShellView::Story) {
            self.go_back();
        } else {
            self.show_story();
        }
    }
}

fn target_revision_refresh_effects() -> Vec<ShellEffect> {
    vec![
        ShellEffect::RefreshFindings(FindingsRefresh {
            announce: false,
            filter: None,
        }),
        ShellEffect::RefreshProgramScope,
    ]
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

fn root_target_scope() -> TargetCandidateScope {
    TargetCandidateScope {
        id: kuzushi_core::workspace::ROOT_SCOPE_ID.to_string(),
        kind: kuzushi_core::NestedProjectKind::Root,
        rel_path: ".".to_string(),
    }
}

fn component_scope_from_state(
    state: &ProjectScopeTreeState,
    raw: &str,
) -> Option<TargetCandidateScope> {
    let tree = match state {
        ProjectScopeTreeState::Persisted(tree) => tree,
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
