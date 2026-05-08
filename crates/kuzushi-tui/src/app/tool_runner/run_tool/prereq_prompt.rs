use super::*;

impl ShellApp {
    pub(crate) fn resolve_prereq_prompt(&mut self, reuse: bool) {
        let Some(prompt) = self.pending_prereq_prompt.take() else {
            return;
        };
        let Some(step) = self.drop_current_prereq_step() else {
            return;
        };
        let Ok(workspace) = self.current_workspace() else {
            self.pending_chain = None;
            return;
        };
        if reuse {
            self.log_reused_prereq(&step);
        } else {
            self.requeue_prereq_for_regeneration(step, prompt.current_tool);
        }
        self.advance_chain(workspace);
    }

    pub(crate) fn prompt_for_existing_prereq(&mut self, step: PrereqStep) {
        let final_tool = self
            .pending_chain
            .as_ref()
            .map(|chain| chain.final_tool.clone())
            .unwrap_or_default();
        self.pending_prereq_prompt = Some(PendingPrereqPrompt {
            current_tool: step.tool.clone(),
            current_artifact_path: step.artifact_path.clone(),
            current_artifact_label: step.artifact_label.clone(),
            final_tool,
        });
        self.log(
            "system",
            format!(
                "existing {} at {} - reuse [r] or regenerate [g]?",
                step.artifact_label,
                step.artifact_path.display()
            ),
        );
    }

    fn drop_current_prereq_step(&mut self) -> Option<PrereqStep> {
        self.pending_chain.as_mut()?.drop_first()
    }

    fn log_reused_prereq(&mut self, step: &PrereqStep) {
        self.log(
            "system",
            format!(
                "reusing existing {} at {}",
                step.artifact_label,
                step.artifact_path.display()
            ),
        );
    }

    fn requeue_prereq_for_regeneration(&mut self, step: PrereqStep, current_tool: String) {
        self.log(
            "system",
            format!("regenerating {} via {current_tool}", step.artifact_label),
        );
        let _ = std::fs::remove_file(&step.artifact_path);
        if let Some(chain) = self.pending_chain.as_mut() {
            chain.remaining.insert(0, step);
        }
    }
}
