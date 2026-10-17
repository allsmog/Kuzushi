use super::*;

impl ShellApp {
    pub(crate) fn investigation_allowance_key(&self) -> Option<ViewHydrationKey> {
        if self.target().is_none() || self.shell_view() != ShellView::Workbench {
            return None;
        }
        let page = crate::ui_view_models::active_workbench_page(self);
        let phase = match page {
            WorkbenchPage::Map => WorkflowPhase::Map,
            WorkbenchPage::Scan | WorkbenchPage::Review => WorkflowPhase::Scan,
            _ => return None,
        };
        let attempt = self
            .allowance_phase_attempt(phase, page == WorkbenchPage::Review)
            .or_else(|| {
                self.engagement
                    .displayed_phase_attempt(WorkflowPhase::Map)
                    .map(|(attempt, _)| attempt)
            })?;
        let run_refs = attempt.completed.run_refs.clone();
        (!run_refs.is_empty()).then_some(ViewHydrationKey::InvestigationAllowance { run_refs })
    }

    fn allowance_phase_attempt(
        &self,
        phase: WorkflowPhase,
        selected: bool,
    ) -> Option<&kuzushi_core::workflow_attempts::PhaseAttemptRecord> {
        if selected {
            return self
                .engagement
                .selected_phase_attempt(phase)
                .or_else(|| self.engagement.stale_selected_phase_attempt(phase));
        }
        self.engagement
            .displayed_phase_attempt(phase)
            .map(|(attempt, _)| attempt)
    }
}

#[cfg(test)]
mod tests;
