use super::*;

impl ShellApp {
    pub(crate) fn start_prereq_chain(
        &mut self,
        steps: Vec<PrereqStep>,
        final_tool: String,
        final_input: serde_json::Value,
        workspace: WorkspaceTarget,
        thinking_level: Option<String>,
    ) {
        let chain = PrereqChain::new(steps, final_tool, final_input, thinking_level);
        self.pending_chain = Some(chain);
        self.present_or_auto_accept_prereq_plan(workspace);
    }

    pub(crate) fn present_or_auto_accept_prereq_plan(&mut self, workspace: WorkspaceTarget) {
        if self.trusted_workflow_auto_accept {
            self.log(
                "system",
                "trusted workflow auto-accepted prerequisite plan via operator config",
            );
            self.accept_prereq_plan(PrereqPlanAction::Approve, workspace);
            return;
        }
        self.pending_prereq_prompt = self.pending_chain.as_ref().map(PrereqChain::plan);
        if let Some(plan) = self.pending_prereq_prompt.clone() {
            let message = prereq_plan_log_line(&plan);
            self.log("system", message);
            self.set_waiting_activity(
                plan.final_tool.clone(),
                "prerequisite plan waiting for approve/reuse/regenerate/cancel",
            );
        }
    }

    pub(crate) fn resolve_prereq_plan(&mut self, action: PrereqPlanAction) {
        let Ok(workspace) = self.current_workspace() else {
            self.pending_chain = None;
            self.pending_prereq_prompt = None;
            self.log(
                "error",
                "cannot resolve prerequisites without an active workspace",
            );
            return;
        };
        match action {
            PrereqPlanAction::Cancel => self.cancel_prereq_plan(),
            PrereqPlanAction::Approve | PrereqPlanAction::Reuse | PrereqPlanAction::Regenerate => {
                self.accept_prereq_plan(action, workspace);
            }
        }
    }

    pub(crate) fn accept_prereq_plan(
        &mut self,
        action: PrereqPlanAction,
        workspace: WorkspaceTarget,
    ) {
        self.pending_prereq_prompt = None;
        let Some(final_tool) = self.mark_prereq_plan_accepted(action) else {
            return;
        };
        self.log(
            "system",
            format!(
                "{final_tool} prerequisite plan accepted: {}",
                action.label()
            ),
        );
        self.advance_chain(workspace);
    }

    pub(crate) fn cancel_prereq_plan(&mut self) {
        let Some(chain) = self.pending_chain.take() else {
            self.pending_prereq_prompt = None;
            return;
        };
        self.pending_prereq_prompt = None;
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
        if self.pending_chain_approved() {
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

    pub(crate) fn advance_chain_after_tool(&mut self, tool_name: &str) {
        if self.clear_finished_final_tool(tool_name) {
            return;
        }
        if !self.drop_finished_prereq_step(tool_name) {
            return;
        }
        self.advance_chain_from_current_workspace();
    }

    fn clear_finished_final_tool(&mut self, tool_name: &str) -> bool {
        let finished = self
            .pending_chain
            .as_ref()
            .is_some_and(|chain| chain.final_dispatched && chain.final_tool == tool_name);
        if finished {
            self.pending_chain = None;
        }
        finished
    }

    fn drop_finished_prereq_step(&mut self, tool_name: &str) -> bool {
        let Some(chain) = self.pending_chain.as_mut() else {
            return false;
        };
        if chain.running_step.as_deref() != Some(tool_name) {
            return false;
        }
        let _ = chain.drop_first();
        chain.running_step = None;
        true
    }

    fn advance_chain_from_current_workspace(&mut self) {
        match self.current_workspace() {
            Ok(workspace) => self.advance_chain(workspace),
            Err(error) => {
                self.log("error", error.to_string());
                self.pending_chain = None;
            }
        }
    }

    pub(crate) fn abort_pending_chain(&mut self, tool_name: &str) {
        let Some(chain) = self.pending_chain.take() else {
            return;
        };
        self.pending_prereq_prompt = None;
        self.log(
            "system",
            format!(
                "{} prerequisite chain aborted after {tool_name} failed",
                chain.final_tool
            ),
        );
    }

    fn next_prereq_step(&self) -> Option<PrereqStep> {
        self.pending_chain.as_ref()?.next_step().cloned()
    }

    fn pending_chain_approved(&self) -> bool {
        self.pending_chain
            .as_ref()
            .is_some_and(|chain| chain.approved)
    }

    fn mark_prereq_plan_accepted(&mut self, action: PrereqPlanAction) -> Option<String> {
        let chain = self.pending_chain.as_mut()?;
        chain.approved = true;
        chain.regenerate_existing = action == PrereqPlanAction::Regenerate;
        Some(chain.final_tool.clone())
    }

    fn should_reuse_prereq_step(&self, step: &PrereqStep) -> bool {
        self.pending_chain
            .as_ref()
            .is_some_and(|chain| !chain.should_run_step(step))
    }

    fn consume_reusable_prereq_step(&mut self, step: &PrereqStep) -> bool {
        if !self.should_reuse_prereq_step(step) {
            return false;
        }
        self.drop_and_log_reused_prereq_step(step);
        true
    }

    fn drop_and_log_reused_prereq_step(&mut self, step: &PrereqStep) {
        if let Some(chain) = self.pending_chain.as_mut() {
            let _ = chain.drop_first();
        }
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
                self.pending_chain = None;
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
        let final_tool = self
            .pending_chain
            .as_ref()
            .map(|chain| chain.final_tool.clone())
            .unwrap_or_default();
        let thinking = self
            .pending_chain
            .as_ref()
            .and_then(|chain| chain.final_thinking_level.clone());
        if let Some(chain) = self.pending_chain.as_mut() {
            chain.running_step = Some(step.tool.clone());
        }
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
        let Some(chain) = self.pending_chain.as_mut() else {
            return;
        };
        if chain.final_dispatched {
            return;
        }
        chain.final_dispatched = true;
        let tool = chain.final_tool.clone();
        let input = chain.final_input.clone();
        let thinking = chain.final_thinking_level.clone();
        let status = tool_run_status(&tool);
        self.start_background_tool(tool, input, workspace, status, thinking);
    }

    fn prepared_prereq_step_input(
        &self,
        tool_name: &str,
        workspace: &WorkspaceTarget,
    ) -> anyhow::Result<serde_json::Value> {
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: Some(workspace),
            findings_store: None,
            trace: None,
        };
        self.registry
            .prepare_tool_input_for_dispatch(tool_name, serde_json::json!({}), &ctx, None)
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
