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
        self.log(
            "system",
            format!(
                "{}: resolving prerequisites - {}",
                chain.final_tool,
                chain
                    .remaining
                    .iter()
                    .map(|step| step.tool.as_str())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ),
        );
        self.pending_chain = Some(chain);
        self.advance_chain(workspace);
    }

    pub(crate) fn advance_chain(&mut self, workspace: WorkspaceTarget) {
        let Some(step) = self.next_prereq_step() else {
            self.dispatch_final_chain_tool(workspace);
            return;
        };
        if step.artifact_path.exists() {
            self.prompt_for_existing_prereq(step);
        } else {
            self.dispatch_prereq_step(step, workspace);
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

    fn dispatch_prereq_step(&mut self, step: PrereqStep, workspace: WorkspaceTarget) {
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
        self.log(
            "system",
            format!(
                "{} required by {final_tool} - running automatically",
                step.tool
            ),
        );
        let status = tool_run_status(&step.tool);
        self.start_background_tool(
            step.tool,
            serde_json::json!({}),
            workspace,
            status,
            thinking,
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
}
