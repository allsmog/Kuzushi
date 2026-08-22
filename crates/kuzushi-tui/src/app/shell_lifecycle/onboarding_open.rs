use super::*;

impl ShellApp {
    /// Inspect config + workspace + auth state and transition into the
    /// appropriate first-run view. Called by `with_registry` after the
    /// app is constructed; also re-invokable via the `/onboarding`
    /// slash command and the dedicated open_* helpers below.
    pub(crate) fn apply_initial_onboarding_phase(&mut self) {
        let phase = self.compute_initial_onboarding_phase();
        self.log_mcp_attachment_plan();
        self.open_onboarding_phase(phase);
    }

    /// Open the view for a resolved onboarding phase. Shared by the
    /// construction/activation path and the interactive launch path.
    pub(crate) fn open_onboarding_phase(&mut self, phase: InitialOnboardingPhase) {
        match phase {
            InitialOnboardingPhase::Catalog => {}
            InitialOnboardingPhase::TargetPicker => self.open_target_picker(),
            InitialOnboardingPhase::Setup => self.open_setup(),
        }
    }

    /// Emit a one-line summary of which MCP servers will attach to the
    /// next agent call based on which artifacts exist on disk. Called
    /// at shell startup and again whenever a planning task completes so
    /// the operator sees the plan refresh in real time.
    pub(crate) fn log_mcp_attachment_plan(&mut self) {
        let Some(target) = self.target() else {
            return;
        };
        let plan = match kuzushi_core::try_mcp_attachment_plan_for_target(target) {
            Ok(plan) => plan,
            Err(error) => {
                self.log("mcps", format!("MCP plan error: {error:#}"));
                return;
            }
        };
        let summary = if plan.is_empty() {
            "MCP plan: (none) — build artifacts via /planning to attach servers".to_string()
        } else {
            let names: Vec<&str> = plan.iter().map(|a| a.name.as_str()).collect();
            format!("MCP plan: {}", names.join(", "))
        };
        self.log("mcps", summary);
    }

    pub(crate) fn open_model_picker(&mut self) {
        let visible = visible_model_choices(self.config().model.as_deref());
        let selected_index = preferred_visible_model_choice_cursor(self.config());
        self.router
            .model_picker_mut()
            .open(selected_index, visible.len());
        self.router.setup_mut().begin_editor(SetupEditor::Model);
        self.set_shell_view(ShellView::Setup);
        self.log(
            "onboarding",
            "choose a model with ↑/↓/Enter (Esc defers onboarding)",
        );
    }

    pub(crate) fn open_auth_method_picker(&mut self, provider: String) {
        self.router.auth_picker_mut().open(provider.clone());
        self.router
            .setup_mut()
            .begin_editor(SetupEditor::Credentials);
        let label = auth_provider_label(&provider);
        let methods = crate::app::auth_method_rows(&provider)
            .iter()
            .map(|row| row.label)
            .collect::<Vec<_>>()
            .join(", ");
        self.log(
            "onboarding",
            format!("{label} needs credentials · choose {methods} and press Enter"),
        );
        self.set_shell_view(ShellView::Setup);
    }

    /// Inline credential-entry step for a credentialed provider whose
    /// credentials are missing. Replaces the old "log and dump to the
    /// Workbench" dead-end: the operator stays in an actionable surface with
    /// only the compatible credential methods plus the offline demo. No
    /// provider or model is picked here — every mutation stays behind an
    /// explicit Enter on a labeled row, preserving no-silent-fallback.
    pub(crate) fn open_credential_entry(&mut self, provider: String) {
        self.open_auth_method_picker(provider);
    }

    pub(crate) fn open_credential_recovery(&mut self, provider: String) {
        self.router.auth_picker_mut().open_recovery(provider);
        self.router
            .setup_mut()
            .begin_editor(SetupEditor::Credentials);
        self.set_shell_view(ShellView::Setup);
    }

    /// Aggregate pre-engagement readiness surface for a fresh target. Map
    /// recommendations are prepared without marking the engagement phase;
    /// the phase becomes live only when Start Map commits the selected plan.
    pub(crate) fn open_setup(&mut self) {
        let Some(target_root) = self.target_owned() else {
            self.open_target_picker();
            return;
        };
        let (profile, pending) = self.phase_picker_target_profile(&target_root);
        let (rows, selected) =
            self.phase_picker_input(crate::app::WorkflowPhase::Map, profile, &target_root, false);
        self.engagement.planning_picker_mut().open_phase_profiled(
            crate::app::WorkflowPhase::Map,
            rows,
            selected,
            pending,
        );
        self.engagement
            .planning_picker_mut()
            .set_return_to_setup(true);
        self.engagement.clear_phase();
        self.router.setup_mut().open();
        self.set_shell_view(ShellView::Setup);
        if let Some(index) = crate::ui_view_models::setup_readiness_model(self).first_blocker {
            self.router.setup_mut().set_cursor(index);
        }
        self.log(
            "setup",
            "review target, Map plan, model/credentials, prompt, and budget; Start Map commits once ready",
        );
    }

    /// Launch-time target picker for a bare interactive `kuzushi` (no
    /// `--target`). Offers cwd + nearby repos / previous kuzushi targets;
    /// selection re-enters `apply_initial_onboarding_phase` so the chain
    /// continues into the model/auth/planning pickers. Called only from
    /// the interactive terminal path — never construction — so headless
    /// and test apps keep their targetless default.
    pub(crate) fn open_target_picker(&mut self) {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        // A bound target anchors the picker: it is the first, pre-selected
        // candidate and Enter re-confirms it. Opening the picker over an
        // active session must never present it as "no target set" or offer
        // to silently rebind to the process cwd.
        let bound = self.target_owned();
        let first = bound.as_deref().map_or_else(
            || crate::app::immediate_target_candidate(&cwd),
            crate::app::bound_target_candidate,
        );
        self.router.target_picker_mut().open(vec![first]);
        self.runtime_state
            .start_target_candidate_discovery(bound.clone().unwrap_or(cwd));
        if let Some(path) = self
            .router
            .target_picker()
            .selected()
            .map(|candidate| candidate.path.clone())
        {
            self.runtime_state.start_target_candidate_facts(path);
        }
        self.set_shell_view(ShellView::TargetPicker);
        match bound {
            Some(target) => self.log(
                "onboarding",
                format!(
                    "target {} bound — Enter keeps it, or pick another (Esc leaves it unchanged)",
                    target.display()
                ),
            ),
            None => self.log(
                "onboarding",
                "no target set — pick what to scan with ↑/↓/Enter (Esc to browse without one)",
            ),
        }
    }

    pub(crate) fn apply_target_candidate_discovery_results(&mut self) -> bool {
        let results = self.runtime_state.drain_target_candidate_discovery();
        let mut changed = self.apply_pending_active_target_facts();
        let picker_facts = self.runtime_state.drain_target_candidate_facts();
        if self.shell_view() != ShellView::TargetPicker {
            return changed;
        }
        for result in results {
            self.apply_discovered_target_candidates(result.candidates);
            changed = true;
        }
        for stamped in picker_facts {
            self.router.target_picker_mut().apply_facts(stamped.facts);
            changed = true;
        }
        changed
    }

    fn apply_pending_active_target_facts(&mut self) -> bool {
        let mut changed = false;
        for facts in self.runtime_state.drain_active_target_facts() {
            changed |= self.session_mut().apply_active_target_facts(facts);
        }
        changed
    }

    pub(crate) fn start_active_target_facts(&mut self, path: std::path::PathBuf) {
        let generation = self.runtime_state.start_active_target_facts(path.clone());
        self.session_mut()
            .begin_active_target_facts(path, generation);
    }

    pub(crate) fn active_target_facts(&self) -> Option<&crate::app::TargetCandidateFacts> {
        self.session().active_target_facts()
    }

    pub(crate) fn active_target_facts_loading(&self) -> bool {
        self.session().active_target_facts_loading()
    }

    #[cfg(test)]
    pub(crate) fn active_target_facts_path(&self) -> Option<&std::path::Path> {
        self.session().active_target_facts_path()
    }

    fn apply_discovered_target_candidates(&mut self, candidates: Vec<crate::app::TargetCandidate>) {
        self.router
            .target_picker_mut()
            .replace_candidates(candidates);
        if let Some(path) = self
            .router
            .target_picker()
            .selected()
            .map(|candidate| candidate.path.clone())
        {
            self.runtime_state.start_target_candidate_facts(path);
        }
    }

    /// Open the picker for one engagement phase: announce the phase, list only
    /// its tasks, and pre-check the recommended (target-aware) set. Cached
    /// Map artifacts stay unchecked — reused, not rebuilt, unless the operator
    /// presses `g` to regenerate.
    pub(crate) fn open_phase_picker(&mut self, phase: crate::app::WorkflowPhase) {
        self.try_open_phase_picker_with_freshness(phase, false);
    }

    pub(crate) fn open_fresh_map_picker(&mut self) {
        self.try_open_phase_picker_with_freshness(crate::app::WorkflowPhase::Map, true);
    }

    pub(crate) fn try_open_phase_picker(&mut self, phase: crate::app::WorkflowPhase) -> bool {
        self.try_open_phase_picker_with_freshness(phase, false)
    }

    fn try_open_phase_picker_with_freshness(
        &mut self,
        phase: crate::app::WorkflowPhase,
        fresh: bool,
    ) -> bool {
        if !self.prepare_phase_picker_state(phase, fresh) {
            return false;
        }
        self.set_shell_view(ShellView::PlanningPicker);
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
        true
    }

    pub(crate) fn prepare_phase_picker_state(
        &mut self,
        phase: crate::app::WorkflowPhase,
        fresh: bool,
    ) -> bool {
        if self.phase_blocked_by_config(phase) {
            return false;
        }
        let Some(target_root) = self.target_owned() else {
            self.log(
                "error",
                "planning requires an explicit target. Next: target <path> (or target .)",
            );
            return false;
        };
        let (origin_page, origin_view) = self.phase_picker_origin();
        let (profile, pending) = self.phase_picker_target_profile(&target_root);
        let (rows, selected) = self.phase_picker_input(phase, profile, &target_root, fresh);
        self.engagement
            .planning_picker_mut()
            .open_phase_profiled(phase, rows, selected, pending);
        if fresh {
            self.engagement
                .planning_picker_mut()
                .mark_default_cached_for_rebuild();
        }
        self.engagement
            .planning_picker_mut()
            .set_return_to_setup(false);
        self.restore_phase_picker_origin(origin_page, origin_view);
        self.engagement.set_phase(phase);
        true
    }

    /// Capture where the operator actually was before the picker takes over.
    /// Phase navigation from inside the picker keeps the original origin.
    fn phase_picker_origin(&self) -> (Option<WorkbenchPage>, Option<ShellView>) {
        let page = (self.shell_view() == ShellView::Workbench)
            .then(|| crate::ui_view_models::active_workbench_page(self));
        let view = (self.shell_view() != ShellView::PlanningPicker).then(|| self.shell_view());
        (page, view)
    }

    fn restore_phase_picker_origin(
        &mut self,
        origin_page: Option<WorkbenchPage>,
        origin_view: Option<ShellView>,
    ) {
        self.engagement
            .planning_picker_mut()
            .set_origin_workbench_page(origin_page);
        if let Some(view) = origin_view {
            self.engagement
                .planning_picker_mut()
                .set_origin_shell_view(Some(view));
        }
    }

    pub(crate) fn phase_blocked_by_config(&mut self, phase: crate::app::WorkflowPhase) -> bool {
        let Some(stop_after) = self.configured_stop_phase() else {
            return false;
        };
        if phase <= stop_after {
            return false;
        }
        self.engagement.set_phase(stop_after);
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

    pub(crate) fn requested_phase_blocked_by_config(
        &mut self,
        phase: crate::app::WorkflowPhase,
    ) -> bool {
        let Some(stop_after) = self.configured_stop_phase() else {
            return false;
        };
        if phase <= stop_after {
            return false;
        }
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

    pub(crate) fn configured_stop_phase(&self) -> Option<crate::app::WorkflowPhase> {
        self.config()
            .phases
            .stop_after
            .map(guided_phase_to_workflow_phase)
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
        let Some(model_tasks) = self.engagement.model_recommendations() else {
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

    /// A model-backed task can only fail without both a configured model and
    /// credentials for its provider. Keep those rows visible but unchecked;
    /// the picker explains whether the missing prerequisite is model or auth.
    fn drop_model_backed_without_ready_auth(
        &self,
        rows: &[PlanningTaskRow],
        selected: &mut BTreeSet<PlanningTaskId>,
    ) {
        if self.configured_model_auth_ready() {
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
        if !self.engagement.has_failed_tasks() {
            return;
        }
        let failed = self.engagement.failed_task_ids();
        selected.retain(|task| {
            !failed.contains(task)
                && !transitive_dependencies(*task)
                    .iter()
                    .any(|dep| failed.contains(dep))
        });
    }

    fn phase_picker_target_profile(
        &mut self,
        target_root: &std::path::Path,
    ) -> (crate::app::TargetProfile, bool) {
        self.schedule_target_profile_hydration(target_root);
        let state = self
            .workbench_cache()
            .borrow()
            .cached_target_profile(Some(target_root));
        match state {
            ViewDataState::Ready(profile) => (profile, false),
            ViewDataState::NotRequested | ViewDataState::Loading => {
                (crate::app::TargetProfile::conservative(), true)
            }
        }
    }

    fn phase_picker_input(
        &self,
        phase: crate::app::WorkflowPhase,
        profile: crate::app::TargetProfile,
        target_root: &std::path::Path,
        fresh: bool,
    ) -> (Vec<PlanningTaskRow>, BTreeSet<PlanningTaskId>) {
        let mut rows = crate::app::applicable_tasks_for_phase(phase, profile)
            .into_iter()
            .map(|task| PlanningTaskRow::for_task(task, target_root))
            .collect::<Vec<_>>();
        let operations = self.planning_operations(&rows, target_root);
        crate::app::onboarding::overlay_last_attempts(&mut rows, target_root, &operations);
        let mut selected = if fresh {
            fresh_phase_preselection(phase, profile, &rows)
        } else {
            phase_preselection(phase, profile, &rows)
        };
        if phase == crate::app::WorkflowPhase::Map && self.large_repository_needs_decomposition() {
            selected.insert(PlanningTaskId::DecomposeModules);
            selected.insert(PlanningTaskId::GatherRepoContext);
        }
        self.merge_model_recommendations(phase, &rows, &mut selected);
        if !fresh {
            self.drop_failed_dependents(&mut selected);
        }
        self.drop_model_backed_without_ready_auth(&rows, &mut selected);
        (rows, selected)
    }

    fn planning_operations(
        &self,
        rows: &[PlanningTaskRow],
        target_root: &std::path::Path,
    ) -> BTreeMap<PlanningTaskId, crate::app::PlanningOperation> {
        let attempted = crate::app::onboarding::tasks_with_recent_attempts(rows, target_root);
        let Ok(workspace) = kuzushi_core::WorkspaceTarget::new(target_root) else {
            return BTreeMap::new();
        };
        rows.iter()
            .filter(|row| !row.id.is_inline_action())
            .filter(|row| attempted.contains(&row.id))
            .filter_map(|row| {
                self.planning_operation(row.id, &workspace)
                    .map(|op| (row.id, op))
            })
            .collect()
    }

    fn planning_operation(
        &self,
        task: PlanningTaskId,
        workspace: &kuzushi_core::WorkspaceTarget,
    ) -> Option<crate::app::PlanningOperation> {
        let input =
            crate::app::planning_task_explicit_input(task, self.engagement.option_overrides());
        let prepared = self
            .prepare_background_tool_input(task.tool_name(), input, workspace)
            .ok()?;
        Some(crate::app::PlanningOperation {
            prepared_input: prepared.value().clone(),
            operation_fingerprint: prepared.operation_fingerprint().as_str().to_string(),
        })
    }

    fn large_repository_needs_decomposition(&self) -> bool {
        crate::app::large_repository_needs_decomposition(
            self.domain().context_view().files_indexed,
            self.target(),
        )
    }

    pub(crate) fn apply_ready_target_profile(&mut self) {
        let Some(target_root) = self.target_owned() else {
            return;
        };
        let state = self
            .workbench_cache()
            .borrow()
            .cached_target_profile(Some(&target_root));
        let ViewDataState::Ready(profile) = state else {
            return;
        };
        self.engagement.set_target_kind(profile.kind);
        self.log(
            "phase",
            format!("target looks like: {}", profile.kind.as_str()),
        );
        self.refresh_profile_pending_picker(profile, &target_root);
    }

    fn refresh_profile_pending_picker(
        &mut self,
        profile: crate::app::TargetProfile,
        target_root: &std::path::Path,
    ) {
        if !self.engagement.planning_picker().profile_pending() {
            return;
        }
        // The rows being replaced belong to the picker's phase, and
        // `refresh_profiled` swaps rows without touching that stored phase. The
        // engagement can advance past it while profiling is still pending, so
        // rebuilding against the ledger phase would leave the picker holding
        // one phase's rows under another phase's name.
        let Some(phase) = self
            .engagement
            .planning_picker()
            .phase()
            .or_else(|| self.engagement.current_phase())
            .or_else(|| {
                matches!(self.shell_view(), ShellView::Setup)
                    .then_some(crate::app::WorkflowPhase::Map)
            })
        else {
            return;
        };
        let (rows, selected) = self.phase_picker_input(phase, profile, target_root, false);
        self.engagement
            .planning_picker_mut()
            .refresh_profiled(rows, selected);
    }

    fn compute_initial_onboarding_phase(&self) -> InitialOnboardingPhase {
        // Without a target there is nothing for the planning picker to
        // act on, and dropping into the model picker would block every
        // test that constructs a bare `ShellApp` for unrelated
        // assertions. Onboarding only auto-opens when the operator
        // launched the shell with a real workspace. (The pure gate also
        // enforces this via `allow_target_gate = false`; this guard keeps
        // the short-circuit explicit at the construction/activation edge.)
        if self.target().is_none() {
            return InitialOnboardingPhase::Catalog;
        }
        initial_onboarding_phase_for(
            self.config(),
            self.target(),
            self.provider_auth_ready(),
            self.workspace_is_fresh_for_auto_planner(),
        )
    }

    /// Whether the operator's configured provider already has credentials.
    /// Providers that need none (`local:`, unknown) report `false` here only
    /// when no model is set; `auth_ready_for_provider` returns `true` for
    /// them so they never gate.
    fn provider_auth_ready(&self) -> bool {
        self.configured_model_auth_ready()
    }

    /// Provider readiness at the application boundary. Environment/OAuth
    /// probing stays in `auth_ready_for_provider`; session state contributes
    /// only a non-secret marker for a key accepted during this process.
    pub(crate) fn provider_auth_ready_for(&self, provider: &str) -> bool {
        auth_ready_for_provider(provider) || self.session().session_api_key_ready(provider)
    }

    pub(crate) fn configured_model_auth_ready(&self) -> bool {
        self.config()
            .model
            .as_deref()
            .and_then(|model| model.split(':').next())
            .is_some_and(|provider| self.provider_auth_ready_for(provider))
    }

    /// The launch-time onboarding phase for the interactive terminal front
    /// door. Unlike `compute_initial_onboarding_phase`, this permits the
    /// target gate (`allow_target_gate = true`) so a bare `kuzushi` with no
    /// `--target` opens the target picker as the first stage of the gate.
    pub(crate) fn launch_onboarding_phase(&self) -> InitialOnboardingPhase {
        let inputs = crate::app::OnboardingInputs {
            model: self.config().model.as_deref(),
            provider_auth_ready: self.provider_auth_ready(),
            has_target: self.target().is_some(),
            workspace_is_fresh: self.workspace_is_fresh_for_auto_planner(),
            skip_onboarding_env: crate::app::skip_onboarding_env(),
            allow_target_gate: true,
        };
        crate::app::initial_onboarding_phase(&inputs)
    }

    pub(crate) fn open_fresh_planner_or_workbench(&mut self) {
        if self.workspace_is_fresh_for_auto_planner() {
            self.open_setup();
        } else {
            self.open_workbench();
        }
    }

    fn workspace_is_fresh_for_auto_planner(&self) -> bool {
        let Some(target) = self.target() else {
            return false;
        };
        !workspace_has_persisted_findings_for_startup(target)
            && !map_artifact_exists_for_startup(target)
            && !run_summary_exists_for_startup(target)
    }
}

fn workspace_has_persisted_findings_for_startup(target: &std::path::Path) -> bool {
    let Ok(workspace) = kuzushi_core::WorkspaceTarget::new(target) else {
        return false;
    };
    let db_path = workspace.findings_db_path();
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
        .filter_map(|task| task.artifact_path(target))
        .any(|path| path.exists())
}

fn fresh_phase_preselection(
    phase: crate::app::WorkflowPhase,
    profile: crate::app::TargetProfile,
    rows: &[PlanningTaskRow],
) -> BTreeSet<PlanningTaskId> {
    let mut fresh_rows = rows.to_vec();
    for row in &mut fresh_rows {
        row.last_attempt = None;
        if row.artifact_state == crate::app::PlanningArtifactState::Cached {
            row.artifact_state = crate::app::PlanningArtifactState::Missing;
        }
    }
    phase_preselection(phase, profile, &fresh_rows)
}

fn run_summary_exists_for_startup(target: &std::path::Path) -> bool {
    kuzushi_core::run_summary_history_exists(target).unwrap_or(true)
}

fn guided_phase_to_workflow_phase(phase: kuzushi_core::GuidedPhase) -> crate::app::WorkflowPhase {
    match phase {
        kuzushi_core::GuidedPhase::Map => crate::app::WorkflowPhase::Map,
        kuzushi_core::GuidedPhase::Scan => crate::app::WorkflowPhase::Scan,
        kuzushi_core::GuidedPhase::Review => crate::app::WorkflowPhase::Review,
        kuzushi_core::GuidedPhase::Prove => crate::app::WorkflowPhase::Prove,
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[derive(Debug)]
    struct ProfileReader {
        reads: AtomicUsize,
        profile: crate::app::TargetProfile,
    }

    impl ViewArtifactReader for ProfileReader {
        fn read(&self, _target: &std::path::Path, key: &ViewHydrationKey) -> ViewHydrationValue {
            assert_eq!(key, &ViewHydrationKey::TargetProfile);
            self.reads.fetch_add(1, Ordering::SeqCst);
            ViewHydrationValue::TargetProfile(self.profile)
        }
    }

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

    #[test]
    fn targetless_phase_picker_refuses_to_classify_cwd() {
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        let initial_view = app.shell_view();

        app.open_phase_picker(crate::app::WorkflowPhase::Map);

        assert_eq!(app.shell_view(), initial_view);
        assert!(app.engagement.target_kind().is_none());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("requires an explicit target")));
    }

    #[test]
    fn repeated_phase_opens_reuse_one_background_target_profile() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let reader = Arc::new(ProfileReader {
            reads: AtomicUsize::new(0),
            profile: crate::app::TargetProfile::conservative(),
        });
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
        app.set_view_artifact_reader_for_test(reader.clone());

        app.open_phase_picker(crate::app::WorkflowPhase::Map);
        app.open_phase_picker(crate::app::WorkflowPhase::Map);
        wait_for_profile_refresh(&mut app);
        app.open_phase_picker(crate::app::WorkflowPhase::Map);

        assert_eq!(reader.reads.load(Ordering::SeqCst), 1);
        assert!(!app.engagement.planning_picker().profile_pending());
    }

    #[test]
    fn ready_profile_refresh_preserves_operator_selection_delta() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let reader = Arc::new(ProfileReader {
            reads: AtomicUsize::new(0),
            profile: c_target_profile(),
        });
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
        app.set_view_artifact_reader_for_test(reader);
        app.open_phase_picker(crate::app::WorkflowPhase::Scan);
        app.engagement
            .planning_picker_mut()
            .selected_mut()
            .remove(&PlanningTaskId::ScanSecrets);

        wait_for_profile_refresh(&mut app);

        assert!(app
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .any(|row| row.id == PlanningTaskId::HuntSystems));
        assert!(!app
            .engagement
            .planning_picker()
            .selected()
            .contains(&PlanningTaskId::ScanSecrets));
    }

    #[test]
    fn large_undecomposed_repo_preselects_decomposition_before_threat_modeling() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
        app.domain_mut().context_view_mut().files_indexed = Some(81_259);

        app.open_phase_picker(crate::app::WorkflowPhase::Map);

        let picker = app.engagement.planning_picker();
        assert!(picker
            .selected()
            .contains(&PlanningTaskId::DecomposeModules));
        let decompose = picker
            .tasks()
            .iter()
            .position(|row| row.id == PlanningTaskId::DecomposeModules)
            .unwrap();
        let threat_model = picker
            .tasks()
            .iter()
            .position(|row| row.id == PlanningTaskId::BuildThreatModel)
            .unwrap();
        assert!(decompose < threat_model);
    }

    #[test]
    fn returned_planner_reads_decomposition_from_the_canonical_v3_path() {
        let target = tempfile::tempdir().unwrap();
        let workspace = kuzushi_core::WorkspaceTarget::new(target.path()).unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), Some(&workspace));
        app.domain_mut().context_view_mut().files_indexed = Some(81_259);
        app.open_phase_picker(crate::app::WorkflowPhase::Map);

        std::fs::create_dir_all(target.path().join("packages/api")).unwrap();
        std::fs::write(target.path().join("packages/api/package.json"), "{}").unwrap();
        let tree = kuzushi_core::discover_nested_project_scopes(target.path());
        let path = kuzushi_core::save_nested_project_scopes(target.path(), &tree).unwrap();
        assert_eq!(
            path,
            kuzushi_core::workspace::project_model_scopes_path(target.path())
        );

        app.open_phase_picker(crate::app::WorkflowPhase::Map);

        let row = app
            .engagement
            .planning_picker()
            .tasks()
            .iter()
            .find(|row| row.id == PlanningTaskId::DecomposeModules)
            .unwrap();
        assert_eq!(
            row.artifact_state,
            crate::app::PlanningArtifactState::Cached
        );
        assert!(!app
            .engagement
            .planning_picker()
            .selected()
            .contains(&PlanningTaskId::DecomposeModules));
    }

    fn c_target_profile() -> crate::app::TargetProfile {
        crate::app::TargetProfile {
            kind: kuzushi_core::TargetKind::Source,
            has_c_family_source: true,
            has_rust_source: false,
            has_compile_commands: false,
            has_reverse_engineering_artifact: false,
        }
    }

    fn wait_for_profile_refresh(app: &mut ShellApp) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while app.engagement.planning_picker().profile_pending() && Instant::now() < deadline {
            app.apply_view_hydration_results();
            std::thread::yield_now();
        }
        assert!(
            !app.engagement.planning_picker().profile_pending(),
            "target profile did not refresh"
        );
    }
}
