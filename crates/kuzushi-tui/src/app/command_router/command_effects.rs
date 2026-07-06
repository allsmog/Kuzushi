use super::*;
use crate::commands::PatchCommand;

impl ShellApp {
    pub(crate) fn reduce_command_effects(
        &mut self,
        command: &ShellCommand,
    ) -> Option<Vec<ShellEffect>> {
        self.reduce_worker_command_effect(command)
            .or_else(|| self.reduce_option_command_effect(command))
            .or_else(|| self.reduce_workspace_command_effect(command))
            .or_else(|| self.reduce_lifecycle_command_effect(command))
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
            ShellCommand::ThreatRegen => Some(self.reduce_threat_regen()),
            ShellCommand::ThreatAsk(question) => Some(self.reduce_threat_ask(question)),
            ShellCommand::ThreatApply => Some(self.reduce_threat_apply()),
            ShellCommand::Patch(PatchCommand::Apply) => Some(self.reduce_patch_apply()),
            ShellCommand::Patch(PatchCommand::Regen { style }) => {
                Some(self.reduce_patch_regen(style))
            }
            ShellCommand::ReviewDecision(command) => {
                Some(self.reduce_review_decision_command(command))
            }
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

    fn reduce_lifecycle_command_effect(&self, command: &ShellCommand) -> Option<Vec<ShellEffect>> {
        match command {
            ShellCommand::Cancel => Some(vec![ShellEffect::CancelActiveJobs]),
            ShellCommand::Quit => Some(vec![ShellEffect::Quit]),
            _ => None,
        }
    }

    pub(crate) fn reduce_recommend(&mut self) -> Vec<ShellEffect> {
        self.shell_view = ShellView::Recommend;
        self.catalog_route.reset_recommend_cursor();
        if self.target.is_none() {
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
        self.shell_view = ShellView::Workbench;
        self.workbench_page = Some(crate::app::WorkbenchPage::Terrain);
        self.workbench_focus = crate::app::WorkbenchPane::Center;
        if self.target.is_none() {
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

    pub(crate) fn reduce_patch_apply(&mut self) -> Vec<ShellEffect> {
        let Some(patch) = self.engagement.pending_patch().cloned() else {
            self.log("patch", "no pending patch. Next: run patch:finding");
            return Vec::new();
        };
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(error.to_string(), "target <path> then patch apply"),
                );
                return Vec::new();
            }
        };
        vec![ShellEffect::ApplyReviewedPatch(ReviewedPatchApply {
            alias: patch.alias,
            diff: patch.diff,
            workspace,
        })]
    }
}
