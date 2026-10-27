use super::*;

pub(crate) struct StudyAllowanceSelection<'a> {
    pub(crate) campaign_id: &'a str,
    pub(crate) plan_sha256: Option<&'a str>,
}

impl StudyAllowanceSelection<'_> {
    fn key(&self) -> Option<ViewHydrationKey> {
        Some(ViewHydrationKey::StudyAllowance {
            campaign_id: self.campaign_id.into(),
            plan_sha256: self.plan_sha256?.into(),
        })
    }
}

impl ShellApp {
    pub(crate) fn investigation_allowance_key(&self) -> Option<ViewHydrationKey> {
        if let Some(study) = self.study_allowance_selection() {
            return study.key();
        }
        self.phase_allowance_key()
    }

    pub(crate) fn study_allowance_selection(&self) -> Option<StudyAllowanceSelection<'_>> {
        self.target()?;
        if let Some(id) = self
            .pending_campaign_selection()
            .filter(|_| self.shell_view() == ShellView::Campaign)
        {
            return Some(StudyAllowanceSelection {
                campaign_id: id,
                plan_sha256: None,
            });
        }
        self.matrix_allowance_selection()
            .or_else(|| self.jobs_allowance_selection())
    }

    fn matrix_allowance_selection(&self) -> Option<StudyAllowanceSelection<'_>> {
        let receipt = match self.shell_view() {
            ShellView::Campaign => self.open_matrix_allowance_receipt(),
            ShellView::Workbench => self.reviewed_context_matrix_receipt(),
            _ => None,
        }?;
        Some(StudyAllowanceSelection {
            campaign_id: &receipt.campaign_id,
            plan_sha256: Some(&receipt.plan_sha256),
        })
    }

    fn jobs_allowance_selection(&self) -> Option<StudyAllowanceSelection<'_>> {
        if !self.fixed_jobs_surface() {
            return None;
        }
        let deck = self.router.campaign();
        let selected = deck
            .selected_campaign()
            .filter(|row| crate::app::is_fixed_study_snapshot(row))?;
        Some(StudyAllowanceSelection {
            campaign_id: &selected.campaign_id,
            plan_sha256: deck
                .plan_digests
                .get(&selected.campaign_id)
                .map(String::as_str),
        })
    }

    fn fixed_jobs_surface(&self) -> bool {
        self.shell_view() == ShellView::Campaign
            && self.router.campaign().detail
            && self.router.campaign().batch_scan_config.is_none()
            && self.context_generation().is_none()
    }

    fn open_matrix_allowance_receipt(
        &self,
    ) -> Option<&kuzushi_core::capabilities::campaign::ContextMatrixReceipt> {
        let matrix = &self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .study
            .matrix;
        if !matrix.open {
            return None;
        }
        matrix.receipt.as_ref()
    }

    fn phase_allowance_key(&self) -> Option<ViewHydrationKey> {
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
