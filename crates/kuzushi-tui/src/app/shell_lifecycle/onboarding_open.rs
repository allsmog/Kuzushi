use super::*;

impl ShellApp {
    /// Inspect config + workspace + auth state and transition into the
    /// appropriate first-run view. Called by `with_registry` after the
    /// app is constructed; also re-invokable via the `/onboarding`
    /// slash command and the dedicated open_* helpers below.
    pub(crate) fn apply_initial_onboarding_phase(&mut self) {
        let phase = self.compute_initial_onboarding_phase();
        match phase {
            InitialOnboardingPhase::Catalog => {}
            InitialOnboardingPhase::ModelPicker => self.open_model_picker(),
            InitialOnboardingPhase::AuthMethodPicker { provider } => {
                self.open_auth_method_picker(provider);
            }
            InitialOnboardingPhase::PlanningPicker => self.open_planning_picker(),
        }
    }

    pub(crate) fn open_model_picker(&mut self) {
        self.model_picker_cursor = self
            .model_picker_cursor
            .min(model_choices().len().saturating_sub(1));
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

    pub(crate) fn open_planning_picker(&mut self) {
        let target_root = self.target.clone().unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
        });
        let rows: Vec<PlanningTaskRow> = PlanningTaskId::ALL
            .iter()
            .map(|task| PlanningTaskRow::for_task(*task, &target_root))
            .collect();
        let mut selected: BTreeSet<PlanningTaskId> = rows
            .iter()
            .filter(|row| row.pre_checked())
            .map(|row| row.id)
            .collect();
        // Always include transitive deps of pre-checked rows so the run
        // plan stays valid.
        let original: Vec<PlanningTaskId> = selected.iter().copied().collect();
        for task in original {
            selected.extend(transitive_dependencies(task));
        }
        self.planning_tasks = rows;
        self.planning_selected = selected;
        self.planning_cursor = 0;
        self.shell_view = ShellView::PlanningPicker;
        self.log(
            "onboarding",
            "select planning tasks with Space; Enter to run, Esc to skip",
        );
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
