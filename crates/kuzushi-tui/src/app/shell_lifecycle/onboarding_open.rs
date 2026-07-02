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
        self.picker_focus = crate::app::PickerFocus::List;
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
        self.picker_focus = crate::app::PickerFocus::List;
        self.auth_picker_cursor = 0;
        self.auth_key_draft.clear();
        self.log(
            "onboarding",
            format!("{provider} supports multiple auth methods — paste an API key or pick OAuth"),
        );
        self.shell_view = ShellView::AuthMethodPicker(provider);
    }

    /// Open the launch picker at the first phase (組 KUMI-KATA · map).
    /// Constructing an app in tests never spawns a background tool here.
    pub(crate) fn open_planning_picker(&mut self) {
        self.open_phase_picker(crate::app::WorkflowPhase::Map);
    }

    /// Launch-time target picker for a bare interactive `kuzushi` (no
    /// `--target`). Offers cwd + nearby repos / previous kuzushi targets;
    /// selection re-enters `apply_initial_onboarding_phase` so the chain
    /// continues into the model/auth/planning pickers. Called only from
    /// the interactive terminal path — never construction — so headless
    /// and test apps keep their targetless default.
    pub(crate) fn open_target_picker(&mut self) {
        self.picker_focus = crate::app::PickerFocus::List;
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        self.target_candidates = crate::app::discover_target_candidates(&cwd);
        self.target_picker_cursor = 0;
        self.shell_view = ShellView::TargetPicker;
        self.log(
            "onboarding",
            "no target set — pick what to scan with ↑/↓/Enter (Esc to browse without one)",
        );
    }

    /// Open the picker for one engagement phase: announce the phase, list only
    /// its tasks, and pre-check the recommended (target-aware) set. Cached
    /// Map artifacts stay unchecked — reused, not rebuilt, unless the operator
    /// presses `g` to regenerate.
    pub(crate) fn open_phase_picker(&mut self, phase: crate::app::WorkflowPhase) {
        if self.phase_blocked_by_config(phase) {
            return;
        }
        let target_root = self.phase_target_root();
        let kind = self.ensure_target_kind(&target_root);
        let target = crate::app::TargetProfile::detect(&target_root, kind);
        let rows: Vec<PlanningTaskRow> = crate::app::applicable_tasks_for_phase(phase, target)
            .into_iter()
            .map(|task| PlanningTaskRow::for_task(task, &target_root))
            .collect();
        let mut selected = phase_preselection(phase, target, &rows);
        self.merge_model_recommendations(phase, &rows, &mut selected);
        self.drop_failed_dependents(&mut selected);
        self.drop_model_backed_without_model(&rows, &mut selected);
        self.planning_tasks = rows;
        self.planning_selected = selected;
        self.planning_rebuild = BTreeSet::new();
        self.planning_cursor = 0;
        self.picker_focus = crate::app::PickerFocus::List;
        self.planning_option_cursor = 0;
        self.planning_option_edit = None;
        self.planning_option_error = None;
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
    }

    fn phase_blocked_by_config(&mut self, phase: crate::app::WorkflowPhase) -> bool {
        let Some(stop_after) = self
            .config
            .phases
            .stop_after
            .map(guided_phase_to_workflow_phase)
        else {
            return false;
        };
        if phase <= stop_after {
            return false;
        }
        self.workflow_phase = Some(stop_after);
        self.log(
            "phase",
            format!(
                "{} stopped by config phases.stop_after={}",
                phase.word(),
                stop_after.word()
            ),
        );
        true
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

    /// With no session model, a model-backed task can only fail — preselecting
    /// it walks the operator straight into a guaranteed error. Leave those rows
    /// unchecked (the picker labels them "needs model"); they stay one Space
    /// away once a model is configured.
    fn drop_model_backed_without_model(
        &self,
        rows: &[PlanningTaskRow],
        selected: &mut BTreeSet<PlanningTaskId>,
    ) {
        if self.config.model.is_some() {
            return;
        }
        let model_backed: BTreeSet<PlanningTaskId> = rows
            .iter()
            .filter(|row| row.model_backed)
            .map(|row| row.id)
            .collect();
        selected.retain(|task| !model_backed.contains(task));
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
            self.workspace_is_fresh_for_auto_planner(),
        )
    }

    pub(crate) fn open_fresh_planner_or_workbench(&mut self) {
        if self.workspace_is_fresh_for_auto_planner() {
            self.open_planning_picker();
        } else {
            self.open_workbench(WorkbenchPane::Findings);
        }
    }

    fn workspace_is_fresh_for_auto_planner(&self) -> bool {
        let Some(target) = self.target.as_deref() else {
            return false;
        };
        !workspace_has_persisted_findings_for_startup(target)
            && !map_artifact_exists_for_startup(target)
            && !run_summary_exists_for_startup(target)
    }
}

fn workspace_has_persisted_findings_for_startup(target: &std::path::Path) -> bool {
    let db_path = kuzushi_core::workspace_findings_db_path(target);
    if !db_path.is_file() {
        return false;
    }
    kuzushi_core::FindingStore::open(&db_path)
        .and_then(|store| store.list_findings(1))
        .is_ok_and(|findings| !findings.is_empty())
}

fn map_artifact_exists_for_startup(target: &std::path::Path) -> bool {
    crate::app::PlanningTaskId::in_phase(crate::app::WorkflowPhase::Map)
        .into_iter()
        .filter_map(crate::app::PlanningTaskId::artifact_relative_path)
        .any(|relative| target.join(relative).exists())
}

fn run_summary_exists_for_startup(target: &std::path::Path) -> bool {
    kuzushi_core::list_run_summaries(target).is_ok_and(|runs| !runs.is_empty())
}

fn guided_phase_to_workflow_phase(phase: kuzushi_core::GuidedPhase) -> crate::app::WorkflowPhase {
    match phase {
        kuzushi_core::GuidedPhase::Map => crate::app::WorkflowPhase::Map,
        kuzushi_core::GuidedPhase::Hunt => crate::app::WorkflowPhase::Hunt,
        kuzushi_core::GuidedPhase::Confirm => crate::app::WorkflowPhase::Confirm,
        kuzushi_core::GuidedPhase::Fix => crate::app::WorkflowPhase::Fix,
    }
}

/// Recommended preselection for a phase plus any within-phase dependencies, so
/// the checked set is always runnable on its own. Cross-phase prerequisites are
/// satisfied by earlier phases and excluded here.
fn phase_preselection(
    phase: crate::app::WorkflowPhase,
    target: crate::app::TargetProfile,
    rows: &[PlanningTaskRow],
) -> BTreeSet<PlanningTaskId> {
    let mut selected = crate::app::recommended_tasks_for_phase(phase, target, rows);
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
        "anthropic" => provider_auth_ready(
            provider,
            std::env::var_os("ANTHROPIC_API_KEY").is_some(),
            &oauth_provider_status("anthropic"),
        ),
        "openai" => provider_auth_ready(
            provider,
            std::env::var_os("OPENAI_API_KEY").is_some(),
            &oauth_provider_status("openai-codex"),
        ),
        "openai-codex" => {
            provider_auth_ready(provider, false, &oauth_provider_status("openai-codex"))
        }
        _ => true,
    }
}

fn provider_auth_ready(provider: &str, api_key_ready: bool, oauth_status: &str) -> bool {
    match provider {
        "anthropic" => api_key_ready || oauth_status.starts_with("stored"),
        "openai" => api_key_ready,
        "openai-codex" => oauth_status.starts_with("stored"),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_oauth_does_not_satisfy_plain_openai_api_key_auth() {
        assert!(!provider_auth_ready(
            "openai",
            false,
            "stored; value hidden"
        ));
        assert!(provider_auth_ready(
            "openai-codex",
            false,
            "stored; value hidden"
        ));
        assert!(provider_auth_ready("openai", true, "missing"));
    }
}
