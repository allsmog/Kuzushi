use super::*;
use kuzushi_core::capabilities::campaign::load_context_study;

impl StudyContextGeneration {
    pub(super) fn refresh_result(&mut self, target: &std::path::Path) {
        self.generated = None;
        self.generated_preview = None;
        self.generated_scopes = None;
        self.generated_lesson = None;
        self.generated_answer = None;
        self.generated_proposal = None;
        self.result_error = None;
        self.rejected_available = false;
        self.rejected_output = None;
        self.show_rejected = false;
        self.refresh_rejected_output_availability(target);
        let Some(receipt) = &self.receipt else {
            return;
        };
        match load_generated_result(receipt, target) {
            Ok(result) => self.apply_generated_result(result),
            Err(error) => self.result_error = Some(format!("{error:#}")),
        }
    }

    fn apply_generated_result(&mut self, result: GeneratedResult) {
        match result {
            GeneratedResult::Context(output) => self.apply_generated_context(output),
            GeneratedResult::Scopes(review) => self.generated_scopes = review,
            GeneratedResult::Lesson(reference) => self.generated_lesson = reference,
            GeneratedResult::Question(answer) => self.generated_answer = answer,
            GeneratedResult::Proposal(proposal) => self.generated_proposal = proposal,
        }
    }

    fn apply_generated_context(
        &mut self,
        output: Option<kuzushi_core::capabilities::campaign::GeneratedStudyContext>,
    ) {
        let Some(output) = output else {
            return;
        };
        self.generated = Some(output.reference.clone());
        self.generated_preview = Some(crate::ui_view_models::context_generation::context_preview(
            output,
        ));
    }

    fn refresh_rejected_output_availability(&mut self, target: &std::path::Path) {
        let Some(receipt) = &self.receipt else {
            return;
        };
        match receipt.rejected_output_available(target) {
            Ok(available) => self.rejected_available = available,
            Err(error) => {
                self.rejected_available = true;
                self.rejected_output = Some(Err(error.to_string()));
            }
        }
    }
}

impl ShellApp {
    pub(crate) fn cache_context_map_result(&mut self, data: &Value) -> bool {
        let state = self.router.campaign_mut();
        let mut updated = false;
        for config in [
            state.batch_scan_config.as_mut(),
            state.setup_context_study.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            updated |= cache_map_attempt(config, data);
            updated |= cache_revision_map_attempt(config, data);
        }
        if updated {
            self.refresh_phase_attempt_projection();
        }
        true
    }

    pub(crate) fn reviewed_context_map_attempt(&self) -> Option<&str> {
        self.study_context_picker()
            .and_then(|picker| picker.map_attempt_id.as_deref())
            .or_else(|| self.context_generation()?.map_attempt_id.as_deref())
    }

    pub(crate) fn restore_context_generation(&mut self, target: &std::path::Path, id: &str) {
        match restore_context_form(target, id) {
            Ok(config) => {
                self.show_study_form(config);
                if self.context_generation().is_none_or(|generation| {
                    !generation.is_scope_proposal()
                        && !generation.is_lesson()
                        && !generation.is_workflow_proposal()
                }) {
                    self.open_study_context_picker();
                }
            }
            Err(error) => {
                self.router.campaign_mut().notice =
                    Some(format!("Context study unavailable: {error:#}"))
            }
        }
    }
}

fn cache_revision_map_attempt(config: &mut BatchScanConfig, data: &Value) -> bool {
    if data["contextOrigin"] != "revision" {
        return false;
    }
    let Some(picker) = config.context_picker.as_mut() else {
        return false;
    };
    let matches =
        serde_json::from_value::<kuzushi_core::ThreatModelRef>(data["modelRef"].clone()).ok();
    if matches.is_none() || matches != picker.selected {
        return false;
    }
    picker.map_attempt_id = data["attemptId"].as_str().map(str::to_string);
    config.notice = Some("Existing context is recorded for Map review. Accept it explicitly before scanning; no model request was made.".into());
    picker.map_attempt_id.is_some()
}

fn cache_map_attempt(config: &mut BatchScanConfig, data: &Value) -> bool {
    let Some((generation, attempt)) = config
        .context_generation
        .as_mut()
        .zip(data["attemptId"].as_str())
    else {
        return false;
    };
    let Some(receipt) = generation.receipt.as_ref() else {
        return false;
    };
    if data["campaignId"] != receipt.campaign_id || data["planSha256"] != receipt.plan_sha256 {
        return false;
    }
    generation.map_attempt_id = Some(attempt.into());
    if let Some(picker) = config.context_picker.as_mut() {
        picker.map_attempt_id = None;
    }
    config.notice = Some("Recorded Map is ready for review. Accept it explicitly before scanning; existing spending is retained.".into());
    true
}

fn restore_context_form(target: &std::path::Path, id: &str) -> Result<BatchScanConfig> {
    let receipt = load_context_study(target, id)?;
    let allowance = receipt.load_allowance(target)?;
    let mut config = BatchScanConfig::load(target, None);
    config.study.investigation_id = receipt.investigation_id.clone();
    super::scoped_context::restore_origin(&mut config, &receipt);
    if let Some(allowance) = allowance {
        config.study.restore_allowance(allowance);
    }
    let mut generation = StudyContextGeneration {
        campaign_id: Some(receipt.campaign_id.clone()),
        context_input: receipt.input.clone(),
        preparation_jobs: serde_json::to_value(&receipt.preparation_jobs)?,
        ..Default::default()
    };
    generation.record_receipt(receipt);
    generation.refresh_result(target);
    config.context_generation = Some(generation);
    Ok(config)
}

enum GeneratedResult {
    Proposal(Option<kuzushi_core::capabilities::campaign::WorkflowProposalResult>),
    Question(Option<kuzushi_core::capabilities::campaign::ContextQuestionAnswer>),
    Context(Option<kuzushi_core::capabilities::campaign::GeneratedStudyContext>),
    Scopes(Option<kuzushi_core::workspace::ScanScopeReview>),
    Lesson(Option<kuzushi_core::findings::LessonRef>),
}

fn load_generated_result(
    receipt: &ContextStudyReceipt,
    target: &std::path::Path,
) -> Result<GeneratedResult> {
    match receipt.generation_tool.as_str() {
        "planner:propose" => receipt
            .workflow_proposal(target)
            .map(GeneratedResult::Proposal),
        "threat-model:ask" => receipt
            .question_answer(target)
            .map(GeneratedResult::Question),
        "findings:lesson-generate" => receipt
            .generated_lesson(target)
            .map(GeneratedResult::Lesson),
        "pack:suggest-scopes" => receipt
            .generated_scopes(target)
            .map(GeneratedResult::Scopes),
        _ => receipt
            .generated_context_document(target)
            .map(GeneratedResult::Context),
    }
}
