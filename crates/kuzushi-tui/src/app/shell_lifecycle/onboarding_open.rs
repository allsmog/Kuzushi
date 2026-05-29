use super::*;

impl ShellApp {
    /// Inspect config + workspace + auth state and transition into the
    /// appropriate first-run view. Called by `with_registry` after the
    /// app is constructed; also re-invokable via the `/onboarding`
    /// slash command and the dedicated open_* helpers below.
    pub(crate) fn apply_initial_onboarding_phase(&mut self) {
        let phase = self.compute_initial_onboarding_phase();
        self.log_mcp_attachment_plan();
        match phase {
            InitialOnboardingPhase::Catalog => {}
            InitialOnboardingPhase::ModelPicker => self.open_model_picker(),
            InitialOnboardingPhase::AuthMethodPicker { provider } => {
                self.open_auth_method_picker(provider);
            }
            InitialOnboardingPhase::PlanningPicker => self.open_planning_picker(),
        }
    }

    /// Emit a one-line summary of which MCP servers will attach to the
    /// next agent call based on which artifacts exist on disk. Called
    /// at shell startup and again whenever a planning task completes so
    /// the operator sees the plan refresh in real time.
    pub(crate) fn log_mcp_attachment_plan(&mut self) {
        let Some(target) = self.target.as_deref() else {
            return;
        };
        let plan = kuzushi_core::mcp_attachment_plan_for_target(target);
        let summary = if plan.is_empty() {
            "MCP plan: (none) — build artifacts via /planning to attach servers".to_string()
        } else {
            let names: Vec<&str> = plan.iter().map(|a| a.name.as_str()).collect();
            format!("MCP plan: {}", names.join(", "))
        };
        self.log("mcps", summary);
    }

    pub(crate) fn open_model_picker(&mut self) {
        let visible = visible_model_choices(self.config.model.as_deref());
        self.model_picker_cursor = self
            .model_picker_cursor
            .min(visible.len().saturating_sub(1));
        self.shell_view = ShellView::ModelPicker;
        self.log(
            "onboarding",
            "no model configured — pick one with ↑/↓/Enter (Esc to defer)",
        );
    }

    pub(crate) fn open_auth_method_picker(&mut self, provider: String) {
        self.auth_picker_cursor = 0;
        self.log(
            "onboarding",
            format!(
                "{provider} supports multiple auth methods — pick one with ↑/↓/Enter (Esc to defer)"
            ),
        );
        self.shell_view = ShellView::AuthMethodPicker(provider);
    }

    /// Open the launch picker at the first phase (組 KUMI-KATA · map). The
    /// session-model ranking is kicked off separately by the interactive launch
    /// path (`request_model_recommendations`), so constructing an app in tests
    /// never spawns a background tool here.
    pub(crate) fn open_planning_picker(&mut self) {
        self.open_phase_picker(crate::app::WorkflowPhase::Map);
    }

    /// Open the picker for one engagement phase: announce the phase, list only
    /// its tasks, and pre-check the recommended (target-aware) set. Cached
    /// Map artifacts stay unchecked — reused, not rebuilt, unless the operator
    /// presses `g` to regenerate.
    pub(crate) fn open_phase_picker(&mut self, phase: crate::app::WorkflowPhase) {
        let target_root = self.phase_target_root();
        let kind = self.ensure_target_kind(&target_root);
        let rows: Vec<PlanningTaskRow> = PlanningTaskId::in_phase(phase)
            .into_iter()
            .map(|task| PlanningTaskRow::for_task(task, &target_root))
            .collect();
        let mut selected = phase_preselection(phase, kind, &rows);
        self.merge_model_recommendations(phase, &rows, &mut selected);
        self.drop_failed_dependents(&mut selected);
        self.planning_tasks = rows;
        self.planning_selected = selected;
        self.planning_rebuild = BTreeSet::new();
        self.planning_cursor = 0;
        self.workflow_phase = Some(phase);
        self.shell_view = ShellView::PlanningPicker;
        self.log(
            "phase",
            format!(
                "{} ({} of {}) — {}",
                phase.label(),
                phase.position(),
                crate::app::WorkflowPhase::ORDER.len(),
                phase.intent()
            ),
        );
        self.log(
            "phase",
            "Space toggle · g rebuild cached · Enter run · Esc skip phase",
        );
    }

    /// Fold this phase's session-model recommendations into the preselection
    /// (additive — the model can suggest tasks the deterministic rules skipped),
    /// pulling in their within-phase dependencies too.
    fn merge_model_recommendations(
        &self,
        phase: crate::app::WorkflowPhase,
        rows: &[PlanningTaskRow],
        selected: &mut BTreeSet<PlanningTaskId>,
    ) {
        let Some(model_tasks) = self.model_recommended_tasks.as_ref() else {
            return;
        };
        let phase_tasks: BTreeSet<PlanningTaskId> = rows.iter().map(|row| row.id).collect();
        for task in crate::app::model_recommended_in_phase(model_tasks, rows, phase) {
            selected.insert(task);
            for dep in transitive_dependencies(task) {
                if phase_tasks.contains(&dep) {
                    selected.insert(dep);
                }
            }
        }
    }

    /// Drop preselections blocked by an earlier-phase failure: a task that
    /// itself failed, or whose prerequisite failed, shouldn't be auto-checked.
    fn drop_failed_dependents(&self, selected: &mut BTreeSet<PlanningTaskId>) {
        if self.planning_failed.is_empty() {
            return;
        }
        let failed: BTreeSet<PlanningTaskId> =
            self.planning_failed.iter().map(|item| item.task).collect();
        selected.retain(|task| {
            !failed.contains(task)
                && !transitive_dependencies(*task)
                    .iter()
                    .any(|dep| failed.contains(dep))
        });
    }

    fn phase_target_root(&self) -> std::path::PathBuf {
        self.target.clone().unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
        })
    }

    /// Classify the target once and cache it; reused across phase pickers.
    fn ensure_target_kind(&mut self, target_root: &std::path::Path) -> kuzushi_core::TargetKind {
        if let Some(kind) = self.target_kind {
            return kind;
        }
        let kind = kuzushi_core::classify_target_kind(target_root);
        self.target_kind = Some(kind);
        self.log("phase", format!("target looks like: {}", kind.as_str()));
        kind
    }

    fn compute_initial_onboarding_phase(&self) -> InitialOnboardingPhase {
        // Without a target there is nothing for the planning picker to
        // act on, and dropping into the model picker would block every
        // test that constructs a bare `ShellApp` for unrelated
        // assertions. Onboarding only auto-opens when the operator
        // launched the shell with a real workspace.
        if self.target.is_none() {
            return InitialOnboardingPhase::Catalog;
        }
        let provider = self
            .config
            .model
            .as_deref()
            .and_then(|model| model.split(':').next());
        let has_multiple_auth = provider
            .map(provider_has_multiple_auth_methods)
            .unwrap_or(false);
        let auth_ready = provider.map(auth_ready_for_provider).unwrap_or(false);
        initial_onboarding_phase_for(
            &self.config,
            self.target.as_deref(),
            auth_ready,
            has_multiple_auth,
        )
    }
}

/// Recommended preselection for a phase plus any within-phase dependencies, so
/// the checked set is always runnable on its own. Cross-phase prerequisites are
/// satisfied by earlier phases and excluded here.
fn phase_preselection(
    phase: crate::app::WorkflowPhase,
    kind: kuzushi_core::TargetKind,
    rows: &[PlanningTaskRow],
) -> BTreeSet<PlanningTaskId> {
    let mut selected = crate::app::recommended_tasks_for_phase(phase, kind, rows);
    let phase_tasks: BTreeSet<PlanningTaskId> = rows.iter().map(|row| row.id).collect();
    for task in selected.iter().copied().collect::<Vec<_>>() {
        for dep in transitive_dependencies(task) {
            if phase_tasks.contains(&dep) {
                selected.insert(dep);
            }
        }
    }
    selected
}

/// Returns true if the operator has credentials wired for `provider` —
/// either via environment variables or via the stored OAuth credentials.
pub(crate) fn auth_ready_for_provider(provider: &str) -> bool {
    match provider {
        "anthropic" => {
            std::env::var_os("ANTHROPIC_API_KEY").is_some()
                || oauth_provider_status("anthropic").starts_with("stored")
        }
        "openai" => std::env::var_os("OPENAI_API_KEY").is_some(),
        "openai-codex" => oauth_provider_status("openai-codex").starts_with("stored"),
        _ => true,
    }
}
