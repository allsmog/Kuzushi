use super::*;

impl ShellApp {
    pub(crate) fn start_prereq_chain(
        &mut self,
        steps: Vec<PrereqStep>,
        final_tool: String,
        final_input: serde_json::Value,
        _workspace: WorkspaceTarget,
        thinking_level: Option<String>,
    ) -> Vec<ShellEffect> {
        let chain = PrereqChain::new(steps, final_tool, final_input, thinking_level);
        self.engagement.set_pending_chain(chain);
        self.present_or_auto_accept_prereq_plan()
    }

    pub(crate) fn present_or_auto_accept_prereq_plan(&mut self) -> Vec<ShellEffect> {
        if self.session().trusted_workflow_auto_accept() {
            self.log(
                "system",
                "trusted workflow auto-accepted prerequisite plan via operator config",
            );
            return self.accept_prereq_plan(PrereqPlanAction::Approve);
        }
        if let Some(plan) = self.engagement.refresh_pending_prereq_prompt() {
            let message = prereq_plan_log_line(&plan);
            self.log("system", message);
            self.set_waiting_activity(
                plan.final_tool.clone(),
                "prerequisite plan waiting for approve/reuse/regenerate/cancel",
            );
        }
        Vec::new()
    }

    pub(crate) fn resolve_prereq_plan(&mut self, action: PrereqPlanAction) -> Vec<ShellEffect> {
        match action {
            PrereqPlanAction::Cancel => {
                self.cancel_prereq_plan();
                Vec::new()
            }
            PrereqPlanAction::Approve | PrereqPlanAction::Reuse | PrereqPlanAction::Regenerate => {
                self.accept_prereq_plan(action)
            }
        }
    }

    pub(crate) fn accept_prereq_plan(&mut self, action: PrereqPlanAction) -> Vec<ShellEffect> {
        self.engagement.clear_pending_prereq_prompt();
        let Some(final_tool) = self.engagement.mark_prereq_plan_accepted(action) else {
            return Vec::new();
        };
        self.log(
            "system",
            format!(
                "{final_tool} prerequisite plan accepted: {}",
                action.label()
            ),
        );
        self.prereq_chain_advance_effect()
    }

    pub(crate) fn cancel_prereq_plan(&mut self) {
        let Some(chain) = self.engagement.take_pending_chain() else {
            self.engagement.clear_pending_prereq_prompt();
            return;
        };
        self.engagement.clear_pending_prereq_prompt();
        self.log(
            "system",
            format!("{} prerequisite plan cancelled", chain.final_tool),
        );
        self.set_refused_activity(
            chain.final_tool,
            "operator cancelled prerequisite plan before dispatch",
        );
    }

    pub(crate) fn advance_chain(&mut self, workspace: WorkspaceTarget) {
        if self.engagement.pending_chain_approved() {
            self.advance_approved_chain(workspace);
        }
    }

    fn advance_approved_chain(&mut self, workspace: WorkspaceTarget) {
        let Some(step) = self.next_runnable_prereq_step() else {
            self.dispatch_final_chain_tool(workspace);
            return;
        };
        self.dispatch_prereq_step(step, workspace);
    }

    fn next_runnable_prereq_step(&mut self) -> Option<PrereqStep> {
        loop {
            let step = self.next_prereq_step()?;
            if !self.consume_reusable_prereq_step(&step) {
                return Some(step);
            }
        }
    }

    pub(crate) fn advance_chain_after_tool(&mut self, tool_name: &str) -> Vec<ShellEffect> {
        if self.engagement.clear_finished_final_tool(tool_name) {
            return Vec::new();
        }
        if !self.engagement.drop_finished_prereq_step(tool_name) {
            return Vec::new();
        }
        self.prereq_chain_advance_effect()
    }

    pub(crate) fn abort_pending_chain(&mut self, tool_name: &str) {
        let Some(chain) = self.engagement.take_pending_chain() else {
            return;
        };
        self.engagement.clear_pending_prereq_prompt();
        self.log(
            "system",
            format!(
                "{} prerequisite chain aborted after {tool_name} failed",
                chain.final_tool
            ),
        );
    }

    fn next_prereq_step(&self) -> Option<PrereqStep> {
        self.engagement.next_prereq_step()
    }

    fn should_reuse_prereq_step(&self, step: &PrereqStep) -> bool {
        self.engagement.should_reuse_prereq_step(step)
    }

    fn consume_reusable_prereq_step(&mut self, step: &PrereqStep) -> bool {
        if !self.should_reuse_prereq_step(step) {
            return false;
        }
        self.drop_and_log_reused_prereq_step(step);
        true
    }

    fn drop_and_log_reused_prereq_step(&mut self, step: &PrereqStep) {
        self.engagement.drop_first_prereq_step();
        self.log(
            "system",
            format!(
                "reusing cached {} at {}",
                step.artifact_label,
                step.artifact_path.display()
            ),
        );
    }

    fn dispatch_prereq_step(&mut self, step: PrereqStep, workspace: WorkspaceTarget) {
        let context = self.prereq_dispatch_context(&step);
        self.log_prereq_dispatch(&step, &context.final_tool);
        let status = tool_run_status(&step.tool);
        let activity = live_activity_for_prereq_step(&step, &context.final_tool);
        let input = match self.prepared_prereq_step_input(&step.tool, &workspace) {
            Ok(input) => input,
            Err(error) => {
                self.log(
                    "error",
                    format!("{} prerequisite input invalid: {error}", step.tool),
                );
                self.engagement.clear_pending_chain();
                return;
            }
        };
        self.start_background_tool_with_activity(
            step.tool,
            input,
            workspace,
            status,
            context.thinking,
            Some(activity),
        );
    }

    fn prereq_dispatch_context(&mut self, step: &PrereqStep) -> PrereqDispatchContext {
        let (final_tool, thinking) = self
            .engagement
            .mark_prereq_step_running(&step.tool)
            .unwrap_or_default();
        PrereqDispatchContext {
            final_tool,
            thinking,
        }
    }

    fn log_prereq_dispatch(&mut self, step: &PrereqStep, final_tool: &str) {
        self.log(
            "system",
            format!(
                "{} required by {final_tool} - running after prerequisite approval; writes {}",
                step.tool,
                prereq_writes_label(step)
            ),
        );
    }

    fn dispatch_final_chain_tool(&mut self, workspace: WorkspaceTarget) {
        let Some((tool, input, thinking)) = self.engagement.mark_final_chain_tool_dispatched()
        else {
            return;
        };
        let status = tool_run_status(&tool);
        self.start_background_tool(tool, input, workspace, status, thinking);
    }

    fn prepared_prereq_step_input(
        &self,
        tool_name: &str,
        workspace: &WorkspaceTarget,
    ) -> anyhow::Result<serde_json::Value> {
        let ctx = ToolExecutionContext {
            config: self.config(),
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
        };
        self.registry().prepare_tool_input_for_dispatch(
            tool_name,
            serde_json::json!({}),
            &ctx,
            None,
        )
    }

    fn prereq_chain_advance_effect(&self) -> Vec<ShellEffect> {
        vec![ShellEffect::AdvancePrereqChain(PrereqChainAdvance {
            target: self.target_owned(),
        })]
    }
}

struct PrereqDispatchContext {
    final_tool: String,
    thinking: Option<String>,
}

fn prereq_writes_label(step: &PrereqStep) -> String {
    step.writes
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn prereq_plan_log_line(plan: &PendingPrereqPrompt) -> String {
    format!(
        "{} needs {} prerequisite(s); review approve/reuse/regenerate/cancel before any prerequisite starts",
        plan.final_tool,
        plan.steps.len()
    )
}
