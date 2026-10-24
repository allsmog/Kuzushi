//! Scope proposals share context planning's finite jobs, allowance and recovery.
use super::*;
use kuzushi_core::workspace::{ScanScopeProposalRef, ScanScopeReview};

impl ShellApp {
    pub(crate) fn open_scope_proposal_study(
        &mut self,
        reference: ScanScopeProposalRef,
        priorities: String,
        omit_context: bool,
    ) -> Result<()> {
        anyhow::ensure!(
            !self.has_running_work(),
            "Wait for active work; your scope draft is preserved."
        );
        anyhow::ensure!(
            priorities.len() <= 2048,
            "Scope priorities exceed 2048 bytes."
        );
        let target = self.target_owned().context("Select a repository first.")?;
        let input = kuzushi_core::capabilities::campaign::scope_proposal_study_input(
            &target,
            reference,
            priorities,
            omit_context,
        )?;
        let mut config = BatchScanConfig::load_for_map_study(&target);
        config.study.ensure_accounting_ready()?;
        config.context_generation = Some(StudyContextGeneration {
            generation_tool: Some("pack:suggest-scopes".into()),
            context_input: input,
            ..Default::default()
        });
        config.notice = Some("One optional AI proposal for the repository. Review its model, exact input and shared allowance. Preparing a draft makes no model request; scopes remain unaccepted and no scan jobs are created.".into());
        self.show_study_form(config);
        Ok(())
    }

    pub(super) fn inspect_generated_scopes(&mut self) -> InputUpdate {
        let Some(review) = self
            .context_generation()
            .and_then(|generation| generation.generated_scopes.clone())
        else {
            return InputUpdate::handled();
        };
        self.install_generated_scope_review(review);
        InputUpdate::handled()
    }

    fn install_generated_scope_review(&mut self, review: ScanScopeReview) {
        self.close_batch_config();
        let Some(target) = self.target_owned() else {
            return;
        };
        if self.scope_review().is_none() {
            *self.router.scope_review_mut() = Some(crate::app::ScopeReviewState::new(target));
        }
        let state = self.router.scope_review_mut().as_mut().unwrap();
        state.install(review);
        state.open = true;
        state.notice = Some("Draft: review before accepting.".into());
    }
}

impl StudyContextGeneration {
    pub(super) fn bind_completed_scope_reference(&mut self) {
        if let Some(review) = &self.generated_scopes {
            self.context_input["proposalRef"] = json!(review.reference);
        }
    }
}
