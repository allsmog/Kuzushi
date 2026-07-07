use super::*;
use crate::commands::PatchCommand;
use kuzushi_core::workspace::findings_since_filter_expression;

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
            .or_else(|| self.reduce_knowledge_command_effect(command))
            .or_else(|| self.reduce_navigation_command_effect(command))
            .or_else(|| self.reduce_view_command_effect(command))
            .or_else(|| self.reduce_engagement_command_effect(command))
            .or_else(|| self.reduce_findings_command_effect(command))
            .or_else(|| self.reduce_terminal_command_effect(command))
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
            ShellCommand::Load(specifier) => Some(self.reduce_load_command(specifier.clone())),
            ShellCommand::Pause => Some(vec![ShellEffect::PauseActiveWork]),
            ShellCommand::Resume(run_id) => Some(vec![ShellEffect::ResumeSession(ResumeSession {
                run_id: run_id.clone(),
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
            _ => None,
        }
    }

    fn reduce_engagement_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Next => {
                self.open_next_phase_picker();
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

    fn reduce_findings_command_effect(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Component(selection) => {
                Some(self.reduce_component_selection(selection.as_deref()))
            }
            ShellCommand::Findings => {
                Some(self.open_workbench_effects(crate::app::WorkbenchPane::Findings))
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
            ShellCommand::Workbench(pane) => Some(self.open_workbench_effects(*pane)),
            _ => None,
        }
    }

    fn reduce_target_navigation_command(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Model(model) => Some(self.reduce_model_command(model)),
            ShellCommand::Scan(target) => Some(vec![ShellEffect::OpenGuidedScan(GuidedScanOpen {
                target: target.clone(),
            })]),
            ShellCommand::ScriptedScan(target) => {
                Some(self.reduce_scan_start(target.clone(), None))
            }
            ShellCommand::Target(path) => Some(self.reduce_target_command(path.as_deref())),
            ShellCommand::TargetRevision(reference) => {
                Some(self.reduce_target_revision_command(reference))
            }
            ShellCommand::Tools(filter) => {
                self.open_tools_view(filter.clone());
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
            ShellCommand::PlanApply => Some(self.reduce_apply_pending_plan()),
            ShellCommand::PlanDiscard => Some(self.reduce_discard_pending_plan()),
            ShellCommand::ThreatRegen => Some(self.reduce_threat_regen()),
            ShellCommand::ThreatAsk(question) => Some(self.reduce_threat_ask(question)),
            ShellCommand::ThreatApply => Some(self.reduce_threat_apply()),
            ShellCommand::Patch(command) => Some(self.reduce_patch_command(command)),
            ShellCommand::ReviewDecision(command) => {
                Some(self.reduce_review_decision_command(command))
            }
            ShellCommand::Strategy(command) => Some(self.reduce_strategy_command(command)),
            ShellCommand::Pwn(command) => Some(self.reduce_pwn_command(command)),
            _ => None,
        }
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
        self.set_shell_view(ShellView::Home);
        self.log("home", "showing Kuzushi cockpit");
    }

    fn open_help_view(&mut self, query: Option<String>) {
        self.set_shell_view(ShellView::Help);
        self.router.help_mut().open(query.clone());
        self.log("help", Self::help_summary(query.as_deref()));
    }

    fn open_modules_view(&mut self) {
        self.set_shell_view(ShellView::Catalog);
        self.router.catalog_mut().expand();
        self.router.modules_mut().open();
        let count = self.registry().modules().count();
        self.log(
            "module",
            format!(
                "showing {count} {}",
                if count == 1 { "module" } else { "modules" }
            ),
        );
    }

    fn open_tools_view(&mut self, filter: Option<String>) {
        self.set_shell_view(ShellView::Tools);
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
            self.log(
                "onboarding",
                "no active workspace target; set one with `target <path>` first",
            );
            return;
        }
        self.open_planning_picker();
    }

    fn open_next_phase_picker(&mut self) {
        self.workbench_cache()
            .borrow_mut()
            .invalidate_map_artifacts();
        let Some(journey) = crate::ui_view_models::journey_model(self) else {
            self.log(
                "journey",
                "no active workspace target; set one with `target <path>` first",
            );
            return;
        };
        self.open_phase_picker(journey.current);
    }

    fn open_requested_phase_picker(&mut self, phase: crate::app::WorkflowPhase) {
        if self.target().is_none() {
            self.log(
                "journey",
                "no active workspace target; set one with `target <path>` first",
            );
            return;
        }
        self.workbench_cache()
            .borrow_mut()
            .invalidate_map_artifacts();
        self.open_phase_picker(phase);
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
        self.set_shell_view(ShellView::Workbench);
        self.router
            .workbench_mut()
            .set_focus(crate::app::WorkbenchPane::Findings);
    }

    fn reduce_findings_since(&mut self, reference: &str) -> Vec<ShellEffect> {
        let expression = match findings_since_filter_expression(self.target(), reference) {
            Ok(expression) => expression,
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(error.to_string(), "target <path> then since <ref>"),
                );
                return Vec::new();
            }
        };
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
        self.set_shell_view(ShellView::Config);
        self.log(
            "permissions",
            "model fallback forbidden without explicit consent; headless run requires explicit tool names",
        );
        self.log(
            "permissions",
            "network egress, filesystem writes outside staged flows, and destructive actions require approval; denial leaves state unchanged",
        );
    }

    fn open_tune_view(&mut self) {
        self.set_shell_view(ShellView::Tune);
        self.log("view", "tune");
    }

    fn focus_module_or_log_error(&mut self, module: &str) {
        if self
            .registry()
            .modules()
            .any(|entry| entry.metadata().id == module)
        {
            self.set_focused_module(Some(module.to_string()));
            self.set_shell_view(ShellView::Module);
            self.log("use", module);
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

    fn help_summary(query: Option<&str>) -> String {
        query.map_or_else(compact_help_summary, |query| {
            format!("filtered command reference for `{query}`")
        })
    }

    pub(crate) fn reduce_recommend(&mut self) -> Vec<ShellEffect> {
        self.set_shell_view(ShellView::Recommend);
        self.router.catalog_mut().reset_recommend_cursor();
        if self.target().is_none() {
            self.log(
                "recommend",
                "choose a target with `target <path>` or run `demo` for the offline fixture",
            );
            return Vec::new();
        }
        if !crate::ui_view_models::recommendation_artifact_needs_refresh(self) {
            self.log("recommend", "latest module recommendations");
            return Vec::new();
        }
        self.log(
            "recommend",
            "running module-recommender:recommend for the active target",
        );
        self.reduce_run_tool(Some("module-recommender:recommend".to_string()), None)
    }

    pub(crate) fn reduce_aim(&mut self, focus: &Option<String>) -> Vec<ShellEffect> {
        self.set_shell_view(ShellView::Workbench);
        self.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Terrain));
        self.router
            .workbench_mut()
            .set_focus(crate::app::WorkbenchPane::Center);
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
        let Some(patch) = self.engagement.pending_patch().cloned() else {
            self.log("patch", "no pending patch. Next: run patch:finding");
            return Vec::new();
        };
        vec![ShellEffect::ApplyReviewedPatch(ReviewedPatchApply {
            alias: patch.alias,
            diff: patch.diff,
            target: self.target_owned(),
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
            .set_page(Some(crate::app::WorkbenchPage::Ship));
        self.log(
            "patch",
            format!("discarded pending patch for {}", patch.alias),
        );
        Vec::new()
    }
}
