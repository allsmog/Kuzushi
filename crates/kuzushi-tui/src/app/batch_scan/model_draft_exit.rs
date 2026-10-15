//! Protect session-only model inputs without restoring work authorization.
use super::{BatchScanConfig, StudyContextGeneration, StudyDraftRecovery};
use crate::app::{ShellApp, ShellView};

impl ShellApp {
    pub(super) fn keep_model_study_choices(&mut self) -> bool {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return false;
        };
        if !lost_on_back(config) || config.draft_recovery != StudyDraftRecovery::None {
            return false;
        }
        config.draft_recovery = StudyDraftRecovery::Discard;
        true
    }

    pub(crate) fn has_session_only_model_study_choices(&self) -> bool {
        let campaign = self.router.campaign();
        [
            campaign.batch_scan_config.as_ref(),
            campaign.setup_context_study.as_ref(),
            campaign.workflow_proposal_study.as_ref(),
            self.router.lessons.generation_study.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(session_only_choices)
    }

    pub(super) fn discard_model_study_choices(&mut self) {
        self.router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .draft_recovery = StudyDraftRecovery::None;
        if self.restore_regeneration_editor() || self.discard_embedded_context_draft() {
            return;
        }
        self.finish_closing_study();
    }

    fn discard_embedded_context_draft(&mut self) -> bool {
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        let Some(generation) = &config.context_generation else {
            return false;
        };
        if generation.is_question() || generation.is_scope_proposal() {
            return false;
        }
        config.context_generation = None;
        config.notice = Some(
            "Context generation draft discarded. Study choices are kept; no work started.".into(),
        );
        true
    }
}

fn session_only_choices(config: &BatchScanConfig) -> bool {
    if let Some(generation) = &config.context_generation {
        return context_choices_unsaved(config, generation);
    }
    config.review_plan.is_some() && review_choices_unsaved(config)
}

fn context_choices_unsaved(config: &BatchScanConfig, generation: &StudyContextGeneration) -> bool {
    generation.receipt.is_none()
        || generation.has_unsaved_guidance()
        || allowance_choices_changed(config)
}

fn review_choices_unsaved(config: &BatchScanConfig) -> bool {
    review_input_changed(config) || allowance_choices_changed(config)
}

fn review_input_changed(config: &BatchScanConfig) -> bool {
    if config.study.review_receipt.is_some() {
        return false;
    }
    let review = config.review_plan.as_ref().unwrap();
    review
        .planning_step
        .as_ref()
        .is_none_or(|step| review.input != step.input)
}

fn allowance_choices_changed(config: &BatchScanConfig) -> bool {
    if let Some(allowance) = &config.study.allowance {
        return (
            config.study.max_provider_calls,
            config.study.protected_review_calls,
        ) != (
            Some(allowance.limits.max_provider_calls as usize),
            Some(allowance.limits.protected_review_calls as usize),
        );
    }
    super::study_checkpoint::resource_choices_changed(config)
}

fn lost_on_back(config: &BatchScanConfig) -> bool {
    if !session_only_choices(config) {
        return false;
    }
    let Some(generation) = &config.context_generation else {
        return true;
    };
    !retained_context_form(config, generation)
}

fn retained_context_form(config: &BatchScanConfig, generation: &StudyContextGeneration) -> bool {
    generation.is_workflow_proposal()
        || generation.is_lesson()
        || unchanged_regeneration(config, generation)
        || setup_form_retained(config, generation)
}

fn setup_form_retained(config: &BatchScanConfig, generation: &StudyContextGeneration) -> bool {
    config
        .origin
        .as_ref()
        .is_some_and(|origin| origin.view == ShellView::Setup)
        && !generation.is_question()
        && !generation.is_scope_proposal()
        && !generation.return_context_editor
}

fn unchanged_regeneration(config: &BatchScanConfig, generation: &StudyContextGeneration) -> bool {
    generation.return_context_editor && !regeneration_choices_changed(config, generation)
}

fn regeneration_choices_changed(
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
) -> bool {
    generation.has_unsaved_guidance()
        || allowance_choices_changed(config)
        || !generation.context_input[generation.editor_field()]
            .as_str()
            .unwrap_or("")
            .is_empty()
}

#[cfg(test)]
mod tests;
