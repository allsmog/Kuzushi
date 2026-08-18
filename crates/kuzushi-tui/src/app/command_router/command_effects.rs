use super::*;
use crate::commands::PatchCommand;
use kuzushi_core::workspace::findings_since_filter_expression;

/// Short registry/activity label for a queued command: the leading verb plus
/// the tool/argument, dropping any trailing JSON payload.
fn steer_command_summary(raw: &str) -> String {
    let head: Vec<&str> = raw.split_whitespace().take(2).collect();
    if head.is_empty() {
        raw.trim().to_string()
    } else {
        head.join(" ")
    }
}

struct ChangedScanRequest {
    input: String,
    path_count: usize,
}

fn changed_scan_request(
    target: &std::path::Path,
    reference: &str,
    include_worktree: bool,
) -> anyhow::Result<Option<ChangedScanRequest>> {
    let scope = kuzushi_core::git_diff_files(target, reference, include_worktree)?;
    let paths = scope
        .files
        .into_iter()
        .filter(|path| target.join(path).is_file())
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return Ok(None);
    }
    Ok(Some(ChangedScanRequest {
        path_count: paths.len(),
        input: serde_json::json!({ "paths": paths, "diffBase": reference }).to_string(),
    }))
}

impl ShellApp {
    pub(crate) fn reduce_command_effects(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        self.reduce_shell_command_effect(command)
            .or_else(|| self.reduce_worker_command_effect(command))
            .or_else(|| self.reduce_option_command_effect(command))
            .or_else(|| self.reduce_workspace_command_effect(command))
            .or_else(|| self.reduce_lifecycle_command_effect(command))
    }

    fn reduce_shell_command_effect(&mut self, command: &ShellCommand) -> Option<Vec<ShellEffect>> {
        self.reduce_status_command_effect(command)
            .or_else(|| self.reduce_scan_command_effect(command))
            .or_else(|| self.reduce_knowledge_command_effect(command))
            .or_else(|| self.reduce_navigation_command_effect(command))
            .or_else(|| self.reduce_view_command_effect(command))
            .or_else(|| self.reduce_engagement_command_effect(command))
            .or_else(|| self.reduce_findings_command_effect(command))
            .or_else(|| self.reduce_jobs_command_effect(command))
            .or_else(|| self.reduce_terminal_command_effect(command))
    }

    fn reduce_scan_command_effect(&mut self, command: &ShellCommand) -> Option<Vec<ShellEffect>> {
        let ShellCommand::ScanSince {
            reference,
            include_worktree,
        } = command
        else {
            return None;
        };
        Some(self.reduce_scan_since(reference, *include_worktree))
    }

    fn reduce_jobs_command_effect(&mut self, command: &ShellCommand) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::ShowJobs => {
                self.open_jobs_view();
                Some(Vec::new())
            }
            ShellCommand::CancelJob(run_id) => Some(self.reduce_cancel_job(run_id)),
            ShellCommand::ShowCampaigns(campaign_id) => {
                self.open_campaign_view(campaign_id.clone());
                Some(Vec::new())
            }
            ShellCommand::ShowCoverage => {
                self.open_coverage_view();
                Some(Vec::new())
            }
            ShellCommand::QueueCommand(raw) => Some(self.reduce_queue_command(raw)),
            ShellCommand::Background => {
                self.background_handoff();
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn reduce_status_command_effect(&mut self, command: &ShellCommand) -> Option<Vec<ShellEffect>> {
        self.reduce_status_view_command_effect(command)
            .or_else(|| self.reduce_status_config_command_effect(command))
            .or_else(|| self.reduce_status_session_command_effect(command))
    }

    fn reduce_status_view_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        self.reduce_primary_status_view_command_effect(command)
            .or_else(|| self.reduce_overlay_status_view_command_effect(command))
    }

    fn reduce_primary_status_view_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Auth => Some(self.reduce_auth_status()),
            ShellCommand::Back => {
                self.go_back();
                Some(Vec::new())
            }
            ShellCommand::Config => {
                self.show_config_status();
                Some(Vec::new())
            }
            ShellCommand::Cost => {
                self.show_cost_status();
                Some(Vec::new())
            }
            ShellCommand::Health => {
                self.open_health_view();
                Some(Vec::new())
            }
            ShellCommand::Help(query) => {
                self.open_help_view(query.clone());
                Some(Vec::new())
            }
            ShellCommand::Home => {
                self.open_home_view();
                Some(Vec::new())
            }
            ShellCommand::History => {
                self.show_history();
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn reduce_overlay_status_view_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::BootSplash => {
                self.set_shell_view(ShellView::BootSplash);
                Some(Vec::new())
            }
            ShellCommand::Keymap => {
                self.set_shell_view(ShellView::Keymap);
                Some(Vec::new())
            }
            ShellCommand::QuitConfirm => {
                self.set_shell_view(ShellView::QuitConfirm);
                Some(Vec::new())
            }
            ShellCommand::ThemePicker => {
                self.set_shell_view(ShellView::ThemePicker);
                Some(Vec::new())
            }
            ShellCommand::UpdateAvailable => {
                self.set_shell_view(ShellView::UpdateAvailable);
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn reduce_status_config_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::AuthLogin(provider) => Some(self.reduce_auth_login_command(provider)),
            ShellCommand::Backend(backend) => {
                self.handle_backend_command(backend.clone());
                Some(Vec::new())
            }
            ShellCommand::Permissions => {
                self.show_permissions_status();
                Some(Vec::new())
            }
            ShellCommand::Provider(provider) => {
                self.handle_provider_command(provider.clone());
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn reduce_status_session_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Clear => Some(vec![ShellEffect::ClearConversation]),
            ShellCommand::SessionInfo => {
                self.show_session_transcript_status();
                Some(Vec::new())
            }
            ShellCommand::Load(specifier) => Some(self.reduce_load_command(specifier.clone())),
            ShellCommand::Pause => Some(vec![ShellEffect::PauseActiveWork]),
            ShellCommand::Resume(run_id) => Some(vec![ShellEffect::ResumeSession(ResumeSession {
                run_id: run_id.clone(),
                from_start: false,
            })]),
            ShellCommand::Retry(run_id) => Some(vec![ShellEffect::ResumeSession(ResumeSession {
                run_id: run_id.clone(),
                from_start: true,
            })]),
            _ => None,
        }
    }

    fn reduce_knowledge_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Context(context_command) => {
                Some(self.reduce_context_command_effects(context_command))
            }
            ShellCommand::FilePicker => Some(vec![ShellEffect::OpenFilePicker]),
            ShellCommand::Modules => {
                self.open_modules_view();
                Some(Vec::new())
            }
            ShellCommand::KnowledgeBase(module) => {
                Some(vec![ShellEffect::ShowKnowledgeBase(KnowledgeBaseShow {
                    module: module.clone(),
                })])
            }
            ShellCommand::Attach(source) => Some(vec![ShellEffect::AttachKnowledgeBaseSource(
                KnowledgeBaseAttach {
                    source: source.clone(),
                },
            )]),
            ShellCommand::Detach(id) => Some(vec![ShellEffect::DetachKnowledgeBaseSource(
                KnowledgeBaseSource { id: id.clone() },
            )]),
            ShellCommand::Reparse(id) => Some(vec![ShellEffect::ReparseKnowledgeBaseSource(
                KnowledgeBaseSource { id: id.clone() },
            )]),
            _ => None,
        }
    }

    fn reduce_navigation_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        self.reduce_run_artifact_navigation_command(command)
            .or_else(|| self.reduce_view_navigation_command(command))
            .or_else(|| self.reduce_target_navigation_command(command))
    }

    fn reduce_run_artifact_navigation_command(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Replay(selector) => {
                Some(self.reduce_open_run_artifact(RunArtifactView::Replay, selector))
            }
            ShellCommand::Trace(selector) => {
                Some(self.reduce_open_run_artifact(RunArtifactView::Trace, selector))
            }
            _ => None,
        }
    }

    fn reduce_view_command_effect(&mut self, command: &ShellCommand) -> Option<Vec<ShellEffect>> {
        self.reduce_general_view_command_effect(command)
            .or_else(|| self.reduce_threat_view_command_effect(command))
    }

    fn reduce_general_view_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        self.reduce_static_view_command_effect(command)
            .or_else(|| self.reduce_artifact_view_command_effect(command))
    }

    fn reduce_static_view_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Actor(index) => {
                self.open_actor_detail(*index);
                Some(Vec::new())
            }
            ShellCommand::FailureHandoff => {
                self.open_failure_handoff();
                Some(Vec::new())
            }
            ShellCommand::Logs => {
                self.show_logs();
                Some(Vec::new())
            }
            ShellCommand::Prompt(raw) => {
                self.set_shell_view(ShellView::PromptsEditor);
                Some(self.reduce_prompt_verb(raw))
            }
            ShellCommand::Prompts => {
                self.open_prompts_view();
                Some(Vec::new())
            }
            ShellCommand::Quickstart => {
                self.show_quickstart();
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn reduce_artifact_view_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::RunDiff { left, right } => {
                self.open_run_diff_view(left.clone(), right.clone());
                Some(Vec::new())
            }
            ShellCommand::Scene => {
                self.open_scene();
                Some(Vec::new())
            }
            ShellCommand::Worklist => {
                self.open_scene_to_page(crate::scene3d::VizPage::Worklist);
                Some(Vec::new())
            }
            ShellCommand::Rail => Some(self.reduce_rail_toggle()),
            ShellCommand::ShowRuns => {
                self.open_runs_view();
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn reduce_threat_view_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Threat(view) => {
                self.open_threat_view(*view);
                Some(Vec::new())
            }
            ShellCommand::ThreatEditor => {
                self.open_threat_editor();
                Some(Vec::new())
            }
            ShellCommand::ThreatReject => {
                self.discard_pending_threat_patch();
                Some(Vec::new())
            }
            ShellCommand::ThreatVersions => {
                self.open_threat_versions();
                Some(Vec::new())
            }
            ShellCommand::ThreatVersionUse(id) => {
                self.use_threat_version(*id);
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn reduce_engagement_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Next | ShellCommand::NextFresh => {
                self.reduce_next_command(matches!(command, ShellCommand::NextFresh));
                Some(Vec::new())
            }
            ShellCommand::Onboarding => {
                self.open_onboarding_picker();
                Some(Vec::new())
            }
            ShellCommand::Options { tool, filter } => {
                self.show_options(tool.clone(), *filter);
                Some(Vec::new())
            }
            ShellCommand::Phase(phase) => {
                self.open_requested_phase_picker(*phase);
                Some(Vec::new())
            }
            ShellCommand::Autonomy(posture) => {
                self.reduce_autonomy_command(*posture);
                Some(Vec::new())
            }
            ShellCommand::ProjectModel => {
                self.open_project_model_view();
                Some(Vec::new())
            }
            ShellCommand::Task(task_command) => {
                Some(self.reduce_sast_task_command(task_command.clone()))
            }
            ShellCommand::Tasks => {
                self.show_sast_tasks();
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn reduce_scan_since(&mut self, reference: &str, include_worktree: bool) -> Vec<ShellEffect> {
        let Some(target) = self.target_owned() else {
            self.log(
                "error",
                "scan since requires an active target. Next: target <path>",
            );
            return Vec::new();
        };
        let request = match changed_scan_request(&target, reference, include_worktree) {
            Ok(Some(request)) => request,
            Ok(None) => {
                self.log(
                    "scan",
                    format!("no existing changed files since {reference}; no scan started"),
                );
                return Vec::new();
            }
            Err(error) => {
                self.log("error", format!("scan since {reference}: {error:#}"));
                return Vec::new();
            }
        };
        let worktree = if include_worktree {
            "including tracked worktree changes"
        } else {
            "committed changes only"
        };
        self.log(
            "scan",
            format!(
                "scanning {} changed file(s) since {reference} ({worktree})",
                request.path_count
            ),
        );
        self.reduce_run_tool(Some("sast:scan".to_string()), Some(request.input))
    }

    fn reduce_findings_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Component(selection) => {
                Some(self.reduce_component_selection(selection.as_deref()))
            }
            ShellCommand::Findings => {
                self.set_active_findings_filter(None);
                self.prepare_findings_list_view();
                Some(self.open_workbench_effects())
            }
            ShellCommand::FindingsFilter(expression) => {
                Some(self.reduce_open_filtered_findings(expression))
            }
            ShellCommand::Open(id) => Some(self.open_finding_effects(id)),
            ShellCommand::ShowAliases(prefix) => {
                self.show_aliases(prefix.as_deref());
                Some(Vec::new())
            }
            ShellCommand::Since(reference) => Some(self.reduce_findings_since(reference)),
            _ => None,
        }
    }

    fn reduce_view_navigation_command(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Story => {
                self.show_story();
                Some(Vec::new())
            }
            ShellCommand::LaunchStartView => {
                open_start_view(self);
                Some(Vec::new())
            }
            ShellCommand::LaunchTargetPicker => {
                self.open_target_picker();
                Some(Vec::new())
            }
            ShellCommand::Tune => {
                self.open_tune_view();
                Some(vec![ShellEffect::RefreshHouseRules(HouseRulesRefresh {
                    path: self.house_rules_path(),
                })])
            }
            ShellCommand::Use(module) => {
                self.focus_module_or_log_error(module);
                Some(Vec::new())
            }
            ShellCommand::Activity => Some(vec![ShellEffect::OpenActivity(ActivityOpen {
                run_id: self.current_activity_run_id(),
            })]),
            ShellCommand::Demo => Some(vec![ShellEffect::StartOfflineDemoFixtureScan]),
            ShellCommand::Workbench => Some(self.open_reality_derived_workbench_effects()),
            ShellCommand::Report => Some(self.open_report_view()),
            _ => None,
        }
    }

    fn open_report_view(&mut self) -> Vec<ShellEffect> {
        self.open_report_from_current_origin();
        Vec::new()
    }

    fn reduce_target_navigation_command(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Model(model) => Some(self.reduce_model_command(model)),
            ShellCommand::Full(target) => Some(self.reduce_full_command(target.clone())),
            ShellCommand::Scan(target) => Some(vec![ShellEffect::OpenGuidedScan(GuidedScanOpen {
                target: target.clone(),
            })]),
            ShellCommand::ScriptedScan(Some(target)) => {
                Some(self.request_target_activation(TargetActivation {
                    path: target.clone(),
                    selected_scope: None,
                    source: TargetActivationSource::ScriptedScan,
                }))
            }
            ShellCommand::ScriptedScan(None) => Some(self.reduce_scan_start(None, None)),
            ShellCommand::Target(path) => Some(self.reduce_target_command(path.as_deref())),
            ShellCommand::TargetRevision(reference) => {
                Some(self.reduce_target_revision_command(reference))
            }
            ShellCommand::Tools(filter) => {
                self.open_tools_view(filter.clone());
                Some(Vec::new())
            }
            ShellCommand::FavoriteTool(tool) => {
                self.toggle_favorite_tool(tool);
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn reduce_worker_command_effect(&mut self, command: &ShellCommand) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Recommend => Some(self.reduce_recommend()),
            ShellCommand::Aim(focus) => Some(self.reduce_aim(focus)),
            ShellCommand::RunTool { tool, input } => {
                Some(self.reduce_run_tool(tool.clone(), input.clone()))
            }
            ShellCommand::Ask(question) => Some(self.reduce_ask_agent(question)),
            ShellCommand::Plan(goal) => Some(self.reduce_planner_start(goal)),
            ShellCommand::PhaseIntent {
                selected_phase,
                text,
            } => Some(self.reduce_phase_intent(*selected_phase, text)),
            ShellCommand::PlanApply => Some(self.reduce_apply_pending_plan()),
            ShellCommand::PlanDiscard => Some(self.reduce_discard_pending_plan()),
            ShellCommand::ThreatRegen => Some(self.reduce_threat_regen()),
            ShellCommand::ThreatAsk(question) => Some(self.reduce_threat_ask(question)),
            ShellCommand::ThreatApply => Some(self.reduce_threat_apply()),
            ShellCommand::Patch(command) => Some(self.reduce_patch_command(command)),
            ShellCommand::ReviewDecision(command) => {
                Some(self.reduce_review_decision_command(command))
            }
            ShellCommand::ProofDeferral { reference, reason } => {
                Some(self.reduce_proof_deferral(reference, reason))
            }
            ShellCommand::Strategy(command) => Some(self.reduce_strategy_command(command)),
            ShellCommand::Pwn(command) => Some(self.reduce_pwn_command(command)),
            _ => None,
        }
    }

    fn reduce_proof_deferral(&mut self, reference: &str, reason: &str) -> Vec<ShellEffect> {
        vec![ShellEffect::RecordProofDeferral(ProofDeferralApply {
            target: self.target_owned(),
            reference: reference.to_string(),
            reason: reason.to_string(),
        })]
    }

    fn reduce_option_command_effect(&mut self, command: &ShellCommand) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::SetOption {
                global,
                name,
                value,
            } => Some(self.reduce_set_option(*global, name, value)),
            ShellCommand::UnsetOption { global, name } => {
                Some(self.reduce_unset_option(*global, name))
            }
            _ => None,
        }
    }

    fn reduce_workspace_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Workspace(workspace_command) => {
                self.reduce_workspace_command_effects(workspace_command)
            }
            _ => None,
        }
    }

    fn reduce_terminal_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Empty => Some(Vec::new()),
            ShellCommand::Unknown(raw) => {
                self.log("error", unknown_command_message(raw));
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn reduce_lifecycle_command_effect(&self, command: &ShellCommand) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Cancel => Some(vec![ShellEffect::CancelActiveJobs]),
            ShellCommand::Quit => Some(vec![ShellEffect::Quit]),
            _ => None,
        }
    }

    fn reduce_open_run_artifact(
        &mut self,
        view: RunArtifactView,
        selector: &str,
    ) -> Vec<ShellEffect> {
        vec![ShellEffect::OpenRunArtifact(OpenRunArtifact {
            selector: selector.to_string(),
            target: self.target_owned(),
            view,
        })]
    }

    fn current_activity_run_id(&self) -> Option<String> {
        self.active_tool_run_id()
            .map(str::to_string)
            .or_else(|| self.scan().and_then(|scan| scan.run_id.clone()))
    }

    fn open_home_view(&mut self) {
        self.clear_focused_module();
        self.router.catalog_mut().collapse();
        self.open_cached_workbench();
        self.log("home", "showing the phase cockpit");
    }

    fn open_help_view(&mut self, query: Option<String>) {
        self.set_shell_view(ShellView::Help);
        self.router.help_mut().open(query.clone());
        self.log("help", Self::help_summary(query.as_deref()));
    }

    fn open_modules_view(&mut self) {
        self.clear_focused_module();
        self.set_shell_view(ShellView::Catalog);
        self.router.catalog_mut().collapse();
        self.router.catalog_mut().jump_start();
        self.router.modules_mut().open();
        let count = self.catalog_module_count();
        self.log(
            "capability",
            format!(
                "showing {count} phase-native {} · press e for expert engines",
                if count == 1 { "action" } else { "actions" }
            ),
        );
    }

    fn toggle_favorite_tool(&mut self, tool: &str) {
        if self.registry().resolve_tool(tool).is_none() {
            self.log("tool", format!("unknown tool {tool:?}"));
            return;
        }
        match self.toggle_tool_favorite(tool) {
            Ok(true) => self.log("tool", format!("★ favorited {tool}")),
            Ok(false) => self.log("tool", format!("☆ unfavorited {tool}")),
            Err(error) => self.log("tool", format!("{error}")),
        }
    }

    fn open_tools_view(&mut self, filter: Option<String>) {
        self.set_shell_view(ShellView::Tools);
        self.reload_tool_shelf();
        if let Some(expr) = filter.as_deref() {
            if let Err(error) = kuzushi_core::modules::ToolQuery::parse(expr) {
                self.log("tool", format!("invalid query {expr:?}: {error}"));
            }
        }
        self.router.tools_mut().open(filter.clone());
        let model = crate::ui_view_models::tools_model(self);
        let suffix = filter
            .as_ref()
            .map(|query| format!(" matching {query:?}"))
            .unwrap_or_default();
        self.log(
            "tool",
            format!(
                "showing {} of {} {}{}",
                model.visible_count,
                model.total_count,
                if model.total_count == 1 {
                    "tool"
                } else {
                    "tools"
                },
                suffix
            ),
        );
    }

    fn open_health_view(&mut self) {
        self.set_shell_view(ShellView::Health);
        self.router.default_scroll_mut().reset();
        let model = crate::ui_view_models::health_model(self);
        self.log("health", model.summary);
    }

    fn open_onboarding_picker(&mut self) {
        if self.target().is_none() {
            self.open_target_picker();
            return;
        }
        self.open_setup();
    }

    fn open_next_phase_picker(&mut self) {
        self.workbench_cache()
            .borrow_mut()
            .invalidate_map_artifacts();
        self.invalidate_view_hydration();
        if let Some(target) = self.target_owned() {
            self.hydrate_view_keys_blocking(
                &target,
                vec![crate::app::ViewHydrationKey::MapArtifacts],
            );
        }
        if !self.open_next_journey_destination() {
            self.open_target_picker();
        }
    }

    pub(crate) fn open_requested_phase_picker(&mut self, phase: crate::app::WorkflowPhase) {
        if self.phase_switch_blocked(phase) {
            return;
        }
        if self.request_phase_target_if_missing(phase) {
            return;
        }
        if self.requested_phase_blocked_by_config(phase) {
            return;
        }
        self.switch_to_requested_phase_picker(phase);
    }

    fn switch_to_requested_phase_picker(&mut self, phase: crate::app::WorkflowPhase) {
        self.workbench_cache()
            .borrow_mut()
            .invalidate_map_artifacts();
        if self.try_open_phase_picker(phase) {
            self.clear_guided_scan();
        }
    }

    fn request_phase_target_if_missing(&mut self, phase: crate::app::WorkflowPhase) -> bool {
        if self.target().is_some() {
            return false;
        }
        self.open_target_picker();
        self.router
            .target_picker_mut()
            .set_pending_intent(PendingTargetIntent::Phase(phase));
        true
    }

    fn phase_switch_blocked(&mut self, phase: crate::app::WorkflowPhase) -> bool {
        if !self.has_running_work() {
            return false;
        }
        self.log(
            "phase",
            format!(
                "{} phase blocked · finish or cancel the active work, then retry",
                phase.word()
            ),
        );
        true
    }

    fn reduce_full_command(&mut self, target: Option<PathBuf>) -> Vec<ShellEffect> {
        if target.is_some() || self.target().is_some() {
            return vec![ShellEffect::OpenGuidedScan(GuidedScanOpen { target })];
        }
        if self.has_running_work() {
            self.log(
                "full",
                "full pipeline blocked · finish or cancel the active work, then retry",
            );
            return Vec::new();
        }
        self.open_target_picker();
        self.router
            .target_picker_mut()
            .set_pending_intent(PendingTargetIntent::Full);
        Vec::new()
    }

    fn reduce_next_command(&mut self, fresh: bool) {
        if fresh {
            self.start_fresh_pass();
        } else {
            self.open_next_phase_picker();
        }
    }

    /// Item 4c: the explicit "start a fresh pass" affordance. Clears the
    /// operator's per-phase draft selections and reopens the Map planner for
    /// this revision. Recorded reality is untouched — completed attempts
    /// stay in the ledger, and the journey re-derives from whatever the new
    /// pass actually runs.
    fn start_fresh_pass(&mut self) {
        self.engagement.planning_picker_mut().reset_phase_drafts();
        self.log(
            "phase",
            "fresh pass — Map planner reopened; prior attempts stay recorded and new Map runs re-derive the journey",
        );
        if self.target().is_none() {
            self.open_target_picker();
            return;
        }
        self.workbench_cache()
            .borrow_mut()
            .invalidate_map_artifacts();
        self.open_fresh_map_picker();
    }

    fn open_project_model_view(&mut self) {
        self.set_shell_view(ShellView::ProjectModel);
        self.router.default_scroll_mut().reset();
        self.log("project", "showing project model aggregate");
    }

    fn reduce_open_filtered_findings(&mut self, expression: &str) -> Vec<ShellEffect> {
        self.open_filtered_findings_view();
        vec![ShellEffect::RefreshFindings(FindingsRefresh {
            announce: true,
            filter: Some(expression.to_string()),
        })]
    }

    fn open_filtered_findings_view(&mut self) {
        self.prepare_findings_list_view();
    }

    fn reduce_findings_since(&mut self, reference: &str) -> Vec<ShellEffect> {
        let expression = match findings_since_filter_expression(self.target(), reference) {
            Ok(expression) => expression,
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(error.to_string(), "target <path> then findings since <ref>"),
                );
                return Vec::new();
            }
        };
        self.log(
            "findings",
            format!("filtered saved findings since {reference}; no scan ran"),
        );
        self.reduce_open_filtered_findings(&expression)
    }

    fn show_config_status(&mut self) {
        self.set_shell_view(ShellView::Config);
        self.sync_selected_model_index();
        self.log(
            "config",
            format!(
                "runtime={} provider={} model={}",
                runtime_backend_label(self.config()),
                self.provider_label(),
                self.config()
                    .model
                    .as_deref()
                    .map(display_model_selector)
                    .unwrap_or_else(|| "unconfigured".to_string())
            ),
        );
    }

    fn show_permissions_status(&mut self) {
        self.set_shell_view(ShellView::Permissions);
        self.log("view", "permission policy");
    }

    fn open_tune_view(&mut self) {
        self.set_shell_view(ShellView::Tune);
        self.log("view", "tune");
    }

    fn focus_module_or_log_error(&mut self, module: &str) {
        if self
            .registry()
            .all_modules()
            .any(|entry| entry.metadata().id == module)
        {
            self.set_focused_module(Some(module.to_string()));
            self.open_tools_view(Some(format!("module:{module}")));
            self.log("use", format!("showing {module} tools"));
        } else {
            self.log("error", self.unknown_module_message(module));
        }
    }

    fn open_actor_detail(&mut self, index: usize) {
        self.router.actor_detail_mut().open(index);
        self.set_shell_view(ShellView::ActorDetail);
        self.log("actor", index.to_string());
    }

    fn open_failure_handoff(&mut self) {
        self.set_shell_view(ShellView::FailureHandoff);
        if self
            .agent_chat()
            .and_then(|agent| agent.failure_context.as_ref())
            .is_some()
        {
            self.log("handoff", "latest bounded failure handoff");
        } else {
            self.log("handoff", "no failure handoff is loaded");
        }
    }

    fn open_prompts_view(&mut self) {
        self.set_shell_view(ShellView::PromptsEditor);
        self.log("view", "prompts");
    }

    fn open_runs_view(&mut self) {
        self.set_shell_view(ShellView::Runs);
        self.log("runs", "recent runs");
    }

    fn open_jobs_view(&mut self) {
        self.set_shell_view(ShellView::Jobs);
        self.router.default_scroll_mut().reset();
        self.log("jobs", "live + recent run registry");
    }

    /// Cancel-by-id. A pending steer item cancels by dequeue (never fires a
    /// token); a live job resolves to its single `JobKind` slot and cancels
    /// **only that job** (`CancelJob`), so the per-row cancel a `Jobs` row
    /// advertises does not abort concurrent jobs. A completed/unknown id
    /// reports honestly rather than pretending to act.
    fn reduce_cancel_job(&mut self, run_id: &str) -> Vec<ShellEffect> {
        if let Some(removed) = self.steer_queue_mut().remove_matching(run_id) {
            self.log("jobs", format!("dropped pending {}", removed.summary));
            return Vec::new();
        }
        match self.resolve_live_job_kind(run_id) {
            Some(kind) => vec![ShellEffect::CancelJob(kind)],
            None => {
                self.log(
                    "jobs",
                    format!("{run_id} is not running; cancel only affects live jobs (see `jobs`)"),
                );
                Vec::new()
            }
        }
    }

    fn resolve_live_job_kind(&self, run_id: &str) -> Option<crate::app::JobKind> {
        use crate::app::JobKind;
        if self.live_run_matches_reference(run_id) {
            return Some(JobKind::Run);
        }
        match run_id {
            "plan" if self.jobs().is_running(JobKind::Plan) => Some(JobKind::Plan),
            "threat" if self.jobs().is_running(JobKind::Threat) => Some(JobKind::Threat),
            _ if self.agent_job_matches_reference(run_id) => Some(JobKind::Agent),
            _ => None,
        }
    }

    fn agent_job_matches_reference(&self, run_id: &str) -> bool {
        use crate::app::JobKind;
        if !self.jobs().is_running(JobKind::Agent) {
            return false;
        }
        if run_id == "agent" {
            return true;
        }
        let Some(agent_id) = self.activity().map(|session| session.run_id.as_str()) else {
            return false;
        };
        matches!(
            resolve_run_reference(run_id, [agent_id]),
            RunReferenceResolution::Resolved(_)
        )
    }

    fn live_run_matches_reference(&self, run_id: &str) -> bool {
        use crate::app::JobKind;
        if !self.jobs().is_running(JobKind::Run) {
            return false;
        }
        let Some(live_id) = self.live_run_id() else {
            return false;
        };
        matches!(
            resolve_run_reference(run_id, [live_id.as_str()]),
            RunReferenceResolution::Resolved(_)
        )
    }

    fn live_run_id(&self) -> Option<String> {
        self.activity()
            .map(|session| session.run_id.clone())
            .or_else(|| self.active_tool_run_id().map(str::to_string))
            .or_else(|| self.scan().and_then(|scan| scan.run_id.clone()))
    }

    /// The explicit `queue <cmd>` verb. Dispatches immediately when nothing is
    /// running (queuing behind nothing would only add a round-trip); otherwise
    /// appends to the steer queue to drain after the live run finishes.
    fn reduce_queue_command(&mut self, raw: &str) -> Vec<ShellEffect> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            self.log("queue", "nothing to queue. Next: queue run <tool>");
            return Vec::new();
        }
        if !self.has_running_work() {
            return self
                .reduce_command_message(crate::commands::parse_command(trimmed))
                .effects;
        }
        self.enqueue_steer_command(trimmed);
        Vec::new()
    }

    /// Append an operator submission to the steer queue and log the depth. The
    /// exact line is stored and re-parsed at drain time so it never captures a
    /// stale option snapshot.
    pub(crate) fn enqueue_steer_command(&mut self, raw: &str) {
        let summary = steer_command_summary(raw);
        self.steer_queue_mut().enqueue(crate::app::QueuedCommand {
            raw: raw.to_string(),
            summary: summary.clone(),
        });
        let depth = self.steer_queue().len();
        self.log(
            "queue",
            format!("queued {summary} — runs after the current job ({depth} pending)"),
        );
    }

    pub(crate) fn submit_run_focus_steer_editor(&mut self) {
        let raw = self
            .router
            .activity()
            .steer_editor
            .as_ref()
            .map(|editor| editor.input.trim().to_string())
            .unwrap_or_default();
        match validate_run_focus_steer(&raw) {
            Ok(command) => {
                self.enqueue_steer_command(&command);
                self.router.activity_mut().close_steer_editor();
            }
            Err(error) => {
                if let Some(editor) = self.router.activity_mut().steer_editor.as_mut() {
                    editor.error = Some(error);
                }
            }
        }
    }

    /// Restore the exact route that launched Run Focus without touching any
    /// cancellation token. A run opened manually has no workflow origin and
    /// falls back to Workbench.
    pub(crate) fn background_handoff(&mut self) {
        let origin = self.activity().and_then(|session| session.run_focus_origin);
        if let Some(session) = self.activity_mut() {
            session.run_focus_backgrounded = true;
            if let Some(origin) = session.run_focus_origin.as_mut() {
                origin.auto_return = false;
            }
        }
        self.set_shell_view(origin.map_or(ShellView::Workbench, |origin| origin.view));
        self.set_input_mode(origin.map_or(InputMode::Prompt, |origin| origin.input_mode));
        if self.has_running_work() {
            self.log(
                "background",
                "job still running in the background — Ctrl+C cancels, `jobs` to check",
            );
        } else {
            self.log("background", "no live job; restored the prior view");
        }
    }

    /// Drain the steer queue after any job finishes. Lowest precedence of the
    /// three "next tool" mechanisms: **chain → plan → steer**. The steer item
    /// stays queued whenever a prereq chain OR the planning queue still has work
    /// pending — the planning advance dispatches its next task through a
    /// *deferred* `DispatchNextPlanningTask` effect, so at drain time nothing
    /// looks running yet; without the `planning_queues_empty` guard the steer
    /// item would be popped and then dropped by the overlap reject.
    pub(crate) fn advance_steer_queue(&mut self) -> Vec<ShellEffect> {
        self.take_next_steer_effects().unwrap_or_default()
    }

    fn take_next_steer_effects(&mut self) -> Option<Vec<ShellEffect>> {
        if self.steer_dispatch_blocked() {
            return None;
        }
        let Some(queued) = self.steer_queue_mut().pop_front() else {
            return None;
        };
        self.log("queue", format!("dispatching queued {}", queued.summary));
        Some(
            self.reduce_command_message(crate::commands::parse_command(&queued.raw))
                .effects,
        )
    }

    /// Keep draining queued synchronous or rejected commands while the shell
    /// remains idle. A bounded pass prevents an arbitrary queue from
    /// monopolizing a terminal tick; commands that start work stop the pass
    /// through `steer_dispatch_blocked` and resume after their terminal event.
    pub(crate) fn drain_idle_steer_queue(&mut self) -> bool {
        const DRAIN_LIMIT: usize = 32;
        let mut changed = false;
        for _ in 0..DRAIN_LIMIT {
            let Some(effects) = self.take_next_steer_effects() else {
                break;
            };
            changed = true;
            EffectRuntime::execute(self, effects);
            if self.steer_dispatch_blocked() {
                break;
            }
        }
        changed
    }

    fn steer_dispatch_blocked(&self) -> bool {
        self.has_running_work()
            || self.engagement.has_pending_chain()
            || self.engagement.has_pending_prereq_prompt()
            || !self.engagement.planning_queues_empty()
            || self.should_quit()
            || matches!(
                self.shell_view(),
                ShellView::QuitConfirm | ShellView::ConfirmDialog
            )
    }

    fn open_run_diff_view(&mut self, left: String, right: String) {
        self.router.run_diff_mut().open(left.clone(), right.clone());
        self.set_shell_view(ShellView::RunDiff);
        self.router.default_scroll_mut().reset();
        self.log("runs", format!("comparing {left} -> {right}"));
    }

    fn open_threat_view(&mut self, view: crate::app::ThreatView) {
        self.router.threat_mut().open(view);
        self.set_shell_view(ShellView::Threat);
        self.log("view", format!("threats {}", threat_view_label(view)));
    }

    fn open_threat_editor(&mut self) {
        self.set_shell_view(ShellView::ThreatEditor);
        self.log("view", "threats edit");
    }

    fn open_threat_versions(&mut self) {
        let Some(target) = self.target_owned() else {
            self.log("threats", "no active target; `target <path>` first");
            return;
        };
        self.refresh_threat_versions(&target);
        self.open_threat_view(crate::app::ThreatView::Versions);
    }

    /// Cap version rows loaded into the view; the ledger itself is unbounded.
    const THREAT_VERSION_LIST_LIMIT: usize = 50;

    fn refresh_threat_versions(&mut self, target: &std::path::Path) {
        match kuzushi_core::list_threat_model_versions(target, Self::THREAT_VERSION_LIST_LIMIT) {
            Ok(versions) => {
                let live_sha256 = kuzushi_core::live_threat_model_sha256(target);
                self.router.threat_mut().set_versions(versions, live_sha256);
            }
            Err(error) => {
                self.log(
                    "error",
                    format!("could not load threat-model versions: {error:#}"),
                );
                self.router.threat_mut().set_versions(Vec::new(), None);
            }
        }
    }

    fn use_threat_version(&mut self, id: i64) {
        let Some(target) = self.target_owned() else {
            self.log("threats", "no active target; `target <path>` first");
            return;
        };
        match kuzushi_core::restore_threat_model_version(&target, id) {
            Ok(version) => {
                self.log(
                    "threats",
                    format!(
                        "version {} is now the live threat model ({} threat(s), source {})",
                        version.id, version.threat_count, version.source
                    ),
                );
                self.hydrate_latest_threat_model_for_dfd();
                self.refresh_threat_versions(&target);
            }
            Err(error) => self.log("error", format!("threats use {id} failed: {error:#}")),
        }
    }

    fn help_summary(query: Option<&str>) -> String {
        query.map_or_else(compact_help_summary, |query| {
            format!("filtered command reference for `{query}`")
        })
    }

    pub(crate) fn reduce_recommend(&mut self) -> Vec<ShellEffect> {
        self.open_modules_view();
        self.log(
            "recommend",
            "phase-native capabilities are derived from workspace reality · press Esc, then e for engines",
        );
        Vec::new()
    }

    pub(crate) fn reduce_aim(&mut self, focus: &Option<String>) -> Vec<ShellEffect> {
        self.set_shell_view(ShellView::Workbench);
        self.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Map));
        self.router
            .workbench_mut()
            .set_focus(crate::ui_view_models::PhaseSurfaceId::MapAttackSurface);
        if self.target().is_none() {
            self.log(
                "aim",
                "choose a target with `target <path>` before seeding the engagement harness",
            );
            return Vec::new();
        }
        self.log("aim", "seeding engagement harness");
        let input = focus
            .as_ref()
            .map(|focus| serde_json::json!({ "focus": focus }).to_string());
        self.reduce_run_tool(Some("engagement:aim".to_string()), input)
    }

    pub(crate) fn reduce_patch_regen(&mut self, style: &Option<String>) -> Vec<ShellEffect> {
        let Some(patch) = self.engagement.pending_patch() else {
            self.log("patch", "no pending patch. Next: run patch:finding");
            return Vec::new();
        };
        let mut input = serde_json::json!({ "fingerprint": patch.alias });
        if let Some(style) = style.as_deref() {
            input["style"] = serde_json::json!(style);
        }
        self.log("patch", "regenerating patch for the current finding");
        self.reduce_run_tool(Some("patch:finding".to_string()), Some(input.to_string()))
    }

    pub(crate) fn reduce_patch_command(&mut self, command: &PatchCommand) -> Vec<ShellEffect> {
        match command {
            PatchCommand::Apply => self.reduce_patch_apply(),
            PatchCommand::Reject => self.reduce_patch_reject(),
            PatchCommand::Regen { style } => self.reduce_patch_regen(style),
            PatchCommand::Unsupported(raw) => {
                self.log(
                    "patch",
                    format!(
                        "unsupported patch command `{raw}`. Next: patch apply, patch reject, or patch regen"
                    ),
                );
                Vec::new()
            }
        }
    }

    pub(crate) fn reduce_patch_apply(&mut self) -> Vec<ShellEffect> {
        let Some(target) = self.target_owned() else {
            self.log("patch", "patch apply requires an active target");
            return Vec::new();
        };
        let selection = match load_durable_fix_selection(&target) {
            Ok(selection) => selection,
            Err(error) => {
                self.log("error", format!("patch apply blocked: {error}"));
                return Vec::new();
            }
        };
        let patch = selection.patch;
        self.engagement.set_pending_patch(patch.clone());
        vec![ShellEffect::ApplyReviewedPatch(ReviewedPatchApply {
            selected_attempt_id: selection.attempt_id,
            alias: patch.alias,
            patch_run_id: patch.patch_run_id,
            diff: patch.diff,
            target: Some(target),
        })]
    }

    fn reduce_patch_reject(&mut self) -> Vec<ShellEffect> {
        let Some(patch) = self.engagement.take_pending_patch() else {
            self.log("patch", "no pending patch to reject");
            return Vec::new();
        };
        self.set_shell_view(ShellView::Workbench);
        self.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Fix));
        self.log(
            "patch",
            format!("discarded pending patch for {}", patch.alias),
        );
        Vec::new()
    }

    /// `rail` toggle with asymmetric persistence: hiding writes the durable
    /// `ui.rail false` policy (a wide terminal stays rail-free next session);
    /// showing restores `ui.rail true` and force-opens for this session only,
    /// so a narrow terminal is not permanently overridden.
    fn reduce_rail_toggle(&mut self) -> Vec<ShellEffect> {
        let columns = self.viewport().columns;
        let visible = crate::ui_view_models::rail_width(self, columns) > 0;
        if visible {
            self.ui_mut().set_rail_force_open(false);
            return self.reduce_set_option(true, crate::app::UI_RAIL_OPTION, "false");
        }
        self.ui_mut().set_rail_force_open(true);
        let effects = self.reduce_set_option(true, crate::app::UI_RAIL_OPTION, "true");
        if crate::ui_view_models::rail_width(self, columns) == 0 {
            self.log(
                "rail",
                format!(
                    "terminal too narrow for the rail ({columns} < {} columns)",
                    crate::ui_view_models::RAIL_FORCE_MIN_WIDTH
                ),
            );
        }
        effects
    }
}

fn validate_run_focus_steer(raw: &str) -> Result<String, String> {
    if !raw.starts_with("run ") {
        return Err("steer accepts only: run <tool> [input]".to_string());
    }
    match crate::commands::parse_command(raw) {
        crate::commands::ShellCommand::RunTool { tool: Some(_), .. } => Ok(raw.to_string()),
        _ => Err("steer requires an explicit tool: run <tool> [input]".to_string()),
    }
}

#[cfg(test)]
mod run_focus_steer_tests {
    use super::*;

    fn git(repo: &std::path::Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn steer_accepts_only_an_explicit_run_command() {
        assert_eq!(
            validate_run_focus_steer("run semgrep:scan {\"path\":\"src\"}"),
            Ok("run semgrep:scan {\"path\":\"src\"}".to_string())
        );
        assert!(validate_run_focus_steer("findings").is_err());
        assert!(validate_run_focus_steer("run").is_err());
        assert!(validate_run_focus_steer("queue run semgrep:scan").is_err());
    }

    #[test]
    fn changed_scan_request_carries_existing_files_and_diff_base() {
        let repo = tempfile::tempdir().unwrap();
        git(repo.path(), &["init", "-q"]);
        git(repo.path(), &["config", "user.email", "test@example.com"]);
        git(repo.path(), &["config", "user.name", "Test"]);
        std::fs::create_dir(repo.path().join("src")).unwrap();
        std::fs::write(repo.path().join("src/lib.rs"), "fn first() {}\n").unwrap();
        git(repo.path(), &["add", "."]);
        git(repo.path(), &["commit", "-qm", "baseline"]);
        let baseline = git(repo.path(), &["rev-parse", "HEAD"]);
        std::fs::write(repo.path().join("src/lib.rs"), "fn changed() {}\n").unwrap();
        git(repo.path(), &["add", "."]);
        git(repo.path(), &["commit", "-qm", "change"]);

        let request = changed_scan_request(repo.path(), &baseline, false)
            .unwrap()
            .expect("changed scan request");
        let input: serde_json::Value = serde_json::from_str(&request.input).unwrap();

        assert_eq!(request.path_count, 1);
        assert_eq!(input["paths"], serde_json::json!(["src/lib.rs"]));
        assert_eq!(input["diffBase"], baseline);
    }

    #[test]
    fn background_restores_the_captured_origin_without_canceling() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let mut session = ActivitySession::new("run-live").with_run_focus_origin(RunFocusOrigin {
            view: ShellView::Home,
            input_mode: InputMode::Navigate,
            auto_return: true,
        });
        session.run_focus_terminal_pending = false;
        app.set_activity(Some(session));
        app.set_shell_view(ShellView::Activity);

        app.background_handoff();

        assert_eq!(app.shell_view(), ShellView::Home);
        assert_eq!(app.input_mode(), InputMode::Navigate);
        assert!(app
            .activity()
            .is_some_and(|session| session.run_focus_backgrounded));
        assert!(app.activity().is_some_and(|session| {
            session
                .run_focus_origin
                .is_some_and(|origin| !origin.auto_return)
        }));
    }

    #[test]
    fn next_fresh_reopens_map_and_marks_cached_defaults_for_one_rebuild() {
        let target = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(target.path()).unwrap();
        workspace.ensure_state_dir().unwrap();
        std::fs::write(target.path().join(".kuzushi/context-snapshot.json"), "{}").unwrap();
        std::fs::write(target.path().join(".kuzushi/entry-points.json"), "{}").unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.reduce_next_command(true);

        assert_eq!(app.shell_view(), ShellView::PlanningPicker);
        let picker = app.engagement.planning_picker();
        for task in [
            PlanningTaskId::GatherRepoContext,
            PlanningTaskId::MapEntryPoints,
        ] {
            assert!(picker.selected().contains(&task), "{task:?} selected");
            assert!(picker.rebuild().contains(&task), "{task:?} rebuild");
        }
    }
}
