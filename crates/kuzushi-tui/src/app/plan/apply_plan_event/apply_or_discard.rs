use super::*;

impl ShellApp {
    pub(crate) fn reduce_apply_pending_plan(&mut self) -> Vec<ShellEffect> {
        if let Err(error) = self.validate_pending_workflow_proposal() {
            self.set_error_notice(
                "plan",
                format!("Proposal actions blocked: {error:#}. The draft is kept for inspection."),
            );
            return Vec::new();
        }
        let Some(plan) = self.take_pending_plan_for_apply() else {
            return Vec::new();
        };
        self.reduce_apply_plan(plan)
    }

    fn validate_pending_workflow_proposal(&self) -> anyhow::Result<()> {
        let Some((target, receipt)) = self.engagement.pending_workflow_proposal() else {
            return Ok(());
        };
        anyhow::ensure!(
            self.target_owned().as_ref() == Some(target),
            "Selected target differs from the proposal target"
        );
        anyhow::ensure!(
            self.config().model.as_deref() == Some(&receipt.model),
            "Selected model changed; prepare a new draft"
        );
        receipt.validate_workflow_proposal_actions(target, self.registry())
    }

    fn take_pending_plan_for_apply(&mut self) -> Option<PlanProposal> {
        match self.engagement.take_pending_plan() {
            Some(plan) => Some(plan),
            None => {
                self.log("plan", "nothing to apply - no plan is pending");
                None
            }
        }
    }

    fn reduce_apply_plan(&mut self, plan: PlanProposal) -> Vec<ShellEffect> {
        let total = plan.changes.len();
        let (applied, effects) = self.reduce_supported_plan_changes(plan.changes);
        self.log("plan", format!("applied {applied}/{total} change(s)"));
        self.reset_plan_review_state();
        self.log_unsupported_plan_changes(plan.unsupported);
        effects
    }

    fn reduce_supported_plan_changes(
        &mut self,
        changes: Vec<PlanChange>,
    ) -> (usize, Vec<ShellEffect>) {
        let mut applied = 0usize;
        let mut effects = Vec::new();
        for (idx, change) in changes.into_iter().enumerate() {
            if self.engagement.plan_change_skipped(idx) {
                continue;
            }
            let (did_apply, mut change_effects) = self.reduce_plan_change(change);
            if did_apply {
                applied += 1;
            }
            effects.append(&mut change_effects);
        }
        (applied, effects)
    }

    fn reset_plan_review_state(&mut self) {
        self.engagement.reset_plan_review_state();
    }

    fn log_unsupported_plan_changes(&mut self, unsupported: Vec<String>) {
        for line in unsupported {
            self.log("plan-skip", line);
        }
    }

    fn reduce_plan_change(&mut self, change: PlanChange) -> (bool, Vec<ShellEffect>) {
        match change {
            PlanChange::RunTool { phase, tool, input } => {
                self.reduce_phase_run_plan_change(phase, tool, input)
            }
            PlanChange::SetOption {
                phase,
                global,
                tool,
                name,
                value,
            } => self.reduce_set_option_plan_change(phase, global, tool, name, value),
            PlanChange::Ask { question } => {
                let update = self.reduce_command_message(ShellCommand::Ask(question));
                (true, update.effects)
            }
            PlanChange::Note { text } => {
                self.log("plan-note", text);
                (true, Vec::new())
            }
        }
    }

    fn reduce_phase_run_plan_change(
        &mut self,
        phase: WorkflowPhase,
        tool: String,
        input: Option<String>,
    ) -> (bool, Vec<ShellEffect>) {
        let declared = kuzushi_core::modules::autonomy::tool_phase(&tool);
        if declared != Some(phase) {
            self.log(
                "plan-skip",
                format!(
                    "refused phase intent tool {tool}: selected {} but descriptor declares {}",
                    phase.label(),
                    declared.map_or("OPERATE", WorkflowPhase::label)
                ),
            );
            return (false, Vec::new());
        }
        let update = self.reduce_command_message(ShellCommand::RunTool {
            tool: Some(tool),
            input,
        });
        (true, update.effects)
    }

    fn reduce_set_option_plan_change(
        &mut self,
        phase: Option<WorkflowPhase>,
        global: bool,
        mut tool: Option<String>,
        name: String,
        value: String,
    ) -> (bool, Vec<ShellEffect>) {
        if let Some(selected_phase) = phase {
            let Some(canonical_tool) =
                self.phase_intent_option_target(selected_phase, tool.as_deref(), &name)
            else {
                return (false, Vec::new());
            };
            tool = Some(canonical_tool);
        }
        let mut effects = Vec::new();
        if let Some(tool_name) = tool {
            let mut update = self.reduce_command_message(ShellCommand::Options {
                tool: Some(tool_name),
                filter: OptionsFilter::Standard,
            });
            effects.append(&mut update.effects);
        }
        let mut update = self.reduce_command_message(ShellCommand::SetOption {
            global,
            name,
            value,
        });
        effects.append(&mut update.effects);
        (true, effects)
    }

    fn phase_intent_option_target(
        &mut self,
        selected_phase: WorkflowPhase,
        tool_name: Option<&str>,
        option_name: &str,
    ) -> Option<String> {
        let tool_name = self.require_phase_option_tool(tool_name)?;
        let Some(facts) = self.phase_option_facts(tool_name, option_name) else {
            self.log(
                "plan-skip",
                format!("refused phase intent option for unknown tool {tool_name}"),
            );
            return None;
        };
        if !self.phase_option_matches(selected_phase, &facts) {
            return None;
        }
        if !facts.option_is_declared {
            self.log(
                "plan-skip",
                format!(
                    "refused phase intent option {}.{option_name}: option is not declared by that tool",
                    facts.canonical_tool
                ),
            );
            return None;
        }
        Some(facts.canonical_tool)
    }

    fn require_phase_option_tool<'a>(&mut self, tool_name: Option<&'a str>) -> Option<&'a str> {
        if tool_name.is_none() {
            self.log(
                "plan-skip",
                "refused phase intent option without an explicit descriptor tool",
            );
        }
        tool_name
    }

    fn phase_option_facts(
        &self,
        tool_name: &str,
        option_name: &str,
    ) -> Option<PhaseIntentOptionFacts> {
        let descriptor = self.registry().resolve_tool(tool_name)?;
        Some(PhaseIntentOptionFacts {
            canonical_tool: descriptor.name.clone(),
            declared_phase: kuzushi_core::modules::autonomy::tool_phase(&descriptor.name),
            option_is_declared: descriptor.options.iter().any(|option| {
                option.name == option_name
                    || option.aliases.iter().any(|alias| alias == option_name)
                    || option
                        .deprecated_aliases
                        .iter()
                        .any(|alias| alias == option_name)
            }),
        })
    }

    fn phase_option_matches(
        &mut self,
        selected_phase: WorkflowPhase,
        facts: &PhaseIntentOptionFacts,
    ) -> bool {
        if facts.declared_phase == Some(selected_phase) {
            return true;
        }
        self.log(
            "plan-skip",
            format!(
                "refused phase intent option for {}: selected {} but descriptor declares {}",
                facts.canonical_tool,
                selected_phase.label(),
                facts.declared_phase.map_or("OPERATE", WorkflowPhase::label)
            ),
        );
        false
    }

    pub(crate) fn reduce_discard_pending_plan(&mut self) -> Vec<ShellEffect> {
        if self.engagement.discard_pending_plan() {
            self.log("plan", "discarded pending plan");
        } else {
            self.log("plan", "nothing to discard - no plan is pending");
        }
        Vec::new()
    }
}

struct PhaseIntentOptionFacts {
    canonical_tool: String,
    declared_phase: Option<WorkflowPhase>,
    option_is_declared: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{OptionScope, OptionTarget, V2Config};

    #[test]
    fn phase_intent_option_writes_only_the_selected_phase_tool() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let (applied, _) = app.reduce_set_option_plan_change(
            Some(WorkflowPhase::Scan),
            false,
            Some("semgrep:scan".to_string()),
            "config".to_string(),
            "auto".to_string(),
        );

        assert!(applied);
        assert_eq!(
            app.option_store()
                .values_for(
                    OptionScope::Session,
                    &OptionTarget::Tool("semgrep:scan".to_string())
                )
                .and_then(|values| values.get("config")),
            Some(&serde_json::json!("auto"))
        );
    }

    #[test]
    fn phase_intent_option_rejects_other_phases_shell_settings_and_implicit_tools() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let cases = [
            (Some("triage:run".to_string()), "strategy".to_string()),
            (
                Some("semgrep:scan".to_string()),
                "ui.auto_open_viz".to_string(),
            ),
            (None, "config".to_string()),
        ];

        for (tool, name) in cases {
            let (applied, effects) = app.reduce_set_option_plan_change(
                Some(WorkflowPhase::Scan),
                false,
                tool,
                name,
                "false".to_string(),
            );
            assert!(!applied);
            assert!(effects.is_empty());
        }

        assert!(app.option_store().is_empty());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| { line.prefix == "plan-skip" && line.body.contains("selected SCAN") }));
    }
}
