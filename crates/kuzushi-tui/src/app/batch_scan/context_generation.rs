use super::{study_actions::allowance_terms, BatchScanConfig, BatchScanConfigRow};
use crate::app::{state_transitions::InputUpdate, ShellApp};
use anyhow::{Context, Result};
use crossterm::event::KeyCode;
use kuzushi_core::{capabilities::campaign::ContextStudyReceipt, ThreatModelRef};
use serde_json::{json, Value};

mod brief;
mod diagnosis;
mod model_selection;
mod recovery;
mod scope_correction;
mod scoped_context;
mod scopes;
pub(crate) use scope_correction::ScopeCorrectionEditor;
mod setup;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct StudyContextGeneration {
    pub(crate) use_brief_guidance: bool,
    pub(crate) show_brief_guidance: bool,
    pub(crate) brief_origin_scroll: usize,
    pub(crate) generation_tool: Option<String>,
    pub(crate) context_input: Value,
    pub(crate) preparation_jobs: Value,
    pub(crate) campaign_id: Option<String>,
    pub(crate) receipt: Option<ContextStudyReceipt>,
    pub(crate) generated: Option<ThreatModelRef>,
    pub(crate) generated_preview:
        Option<crate::ui_view_models::context_generation::GeneratedContextPreview>,
    pub(crate) generated_lesson: Option<kuzushi_core::findings::LessonRef>,
    pub(crate) generated_answer:
        Option<kuzushi_core::capabilities::campaign::ContextQuestionAnswer>,
    pub(crate) generated_proposal:
        Option<kuzushi_core::capabilities::campaign::WorkflowProposalResult>,
    pub(crate) show_answer: bool,
    pub(crate) generated_scopes: Option<kuzushi_core::workspace::ScanScopeReview>,
    pub(crate) scope_correction: Option<ScopeCorrectionEditor>,
    pub(crate) result_error: Option<String>,
    pub(crate) rejected_available: bool,
    pub(crate) rejected_output:
        Option<Result<kuzushi_core::capabilities::campaign::RejectedContextOutput, String>>,
    pub(crate) show_rejected: bool,
    pub(crate) rejected_scroll: usize,
    pub(crate) map_attempt_id: Option<String>,
    pub(crate) scroll: usize,
    pub(crate) show_options: bool,
    pub(crate) show_plan: bool,
    pub(crate) reader_offsets: [usize; 3],
    pub(crate) return_context_editor: bool,
    pub(crate) selected_text_label: Option<String>,
    pub(crate) guidance_editor: Option<crate::app::FieldEditor>,
    pub(crate) guidance_editing: bool,
    pub(crate) guidance_notice: Option<String>,
    pub(crate) options: std::sync::Arc<Vec<String>>,
}

impl StudyContextGeneration {
    pub(crate) fn allows_model_choice(&self) -> bool {
        self.is_scope_proposal()
            || self.is_regeneration()
            || self.is_lesson()
            || self.is_scope_context()
            || self.is_question()
            || self.is_workflow_proposal()
    }
    pub(crate) fn is_scope_context(&self) -> bool {
        self.context_input.get("scanScopeRef").is_some()
            || self.context_input.get("sourcePaths").is_some()
    }
    pub(super) fn has_unsaved_guidance(&self) -> bool {
        self.guidance_editor.as_ref().is_some_and(|editor| {
            editor.text()
                != self.context_input[self.editor_field()]
                    .as_str()
                    .unwrap_or("")
        })
    }
    pub(crate) fn is_regeneration(&self) -> bool {
        self.generation_tool.as_deref() == Some("threat-model:regenerate")
    }
    pub(crate) fn is_question(&self) -> bool {
        self.generation_tool.as_deref() == Some("threat-model:ask")
    }
    pub(crate) fn is_workflow_proposal(&self) -> bool {
        self.generation_tool.as_deref() == Some("planner:propose")
    }
    pub(crate) fn has_text_editor(&self) -> bool {
        self.is_regeneration()
            || self.is_lesson()
            || self.is_question()
            || self.is_workflow_proposal()
    }
    pub(crate) fn editor_field(&self) -> &'static str {
        if self.is_workflow_proposal() {
            return "goal";
        }
        if self.is_question() {
            "question"
        } else {
            "guidance"
        }
    }
    pub(crate) fn editor_limit(&self) -> usize {
        if self.is_workflow_proposal() {
            return 4096;
        }
        if self.is_question() {
            8192
        } else {
            2048
        }
    }
    pub(crate) fn is_scope_proposal(&self) -> bool {
        self.generation_tool.as_deref() == Some("pack:suggest-scopes")
    }
    pub(crate) fn is_lesson(&self) -> bool {
        self.generation_tool.as_deref() == Some("findings:lesson-generate")
    }
    pub(crate) fn supports_rejected_retention(&self) -> bool {
        matches!(
            self.generation_tool.as_deref(),
            None | Some("threat-model:build") | Some("pack:suggest-scopes")
        )
    }

    pub(crate) fn has_result(&self) -> bool {
        self.generated.is_some()
            || self.generated_scopes.is_some()
            || self.generated_lesson.is_some()
            || self.generated_answer.is_some()
            || self.generated_proposal.is_some()
    }
    pub(crate) fn preparation_count(&self) -> usize {
        self.receipt
            .as_ref()
            .map(|r| r.preparation_jobs.len())
            .unwrap_or_else(|| self.preparation_jobs.as_array().map_or(0, Vec::len))
    }

    pub(crate) fn supports_result_overview(&self) -> bool {
        self.supports_rejected_retention()
            && !self.is_scope_proposal()
            && !self.is_scope_context()
            && (self.generated.is_some() || self.result_error.is_some())
    }

    pub(crate) fn shows_result_plan(&self) -> bool {
        self.show_plan && !self.show_options
    }

    fn reader_index(&self) -> usize {
        if self.show_options {
            2
        } else if self.show_plan {
            1
        } else {
            0
        }
    }

    fn select_reader(&mut self, show_plan: bool, show_options: bool) {
        self.reader_offsets[self.reader_index()] = self.scroll;
        self.show_plan = show_plan;
        self.show_options = show_options;
        self.scroll = self.reader_offsets[self.reader_index()];
    }
    pub(crate) fn record_receipt(&mut self, receipt: ContextStudyReceipt) {
        self.use_brief_guidance = receipt.brief_guidance.is_some();
        self.generation_tool = Some(receipt.generation_tool.clone());
        self.options = std::sync::Arc::new(
            crate::ui_view_models::context_generation::format_options(
                &json!({"generationTool":receipt.generation_tool,"contextInput":receipt.input,"preparationJobs":receipt.preparation_jobs}),
            ),
        );
        self.receipt = Some(receipt);
        self.scroll = 0;
        self.show_options = false;
        self.show_plan = false;
        self.reader_offsets = [0; 3];
    }
    pub(crate) fn approved(&self, config: &BatchScanConfig) -> bool {
        let Some((receipt, allowance)) = self.receipt.as_ref().zip(config.study.allowance.as_ref())
        else {
            return false;
        };
        config.study.max_provider_calls == Some(allowance.limits.max_provider_calls as usize)
            && config.study.protected_review_calls
                == Some(allowance.limits.protected_review_calls as usize)
            && receipt.bound_input(allowance).is_ok()
    }

    fn approved_action(&self) -> &'static str {
        if self.is_scope_proposal() {
            return "Open approved scope proposal job";
        }
        if self.preparation_count() == 0 {
            "Open approved context job"
        } else {
            "Open approved Map jobs"
        }
    }

    pub(crate) fn action(&self, config: &BatchScanConfig) -> &'static str {
        if let Some(action) = self.special_action(config) {
            return action;
        }
        if self.result_error.is_some() {
            return "Inspect context job outcome";
        }
        if self.generated.is_some() {
            return "Inspect generated context";
        }
        if self.receipt.is_none() {
            return "Prepare context draft";
        }
        if self.approved(config) {
            return self.approved_action();
        }
        "Review plan and allowance"
    }

    fn special_action(&self, config: &BatchScanConfig) -> Option<&'static str> {
        if self.is_workflow_proposal() {
            return Some(self.workflow_proposal_action(config));
        }
        if self.is_question() {
            return Some(self.question_action(config));
        }
        if self.is_scope_proposal() {
            return Some(self.scope_proposal_action(config));
        }
        if self.is_lesson() {
            return Some(self.lesson_action(config));
        }
        None
    }

    fn scope_proposal_action(&self, config: &BatchScanConfig) -> &'static str {
        if self.has_corrected_scopes() {
            return "Review corrected scope draft";
        }
        if self.result_error.is_some() {
            return "Inspect scope proposal outcome";
        }
        if self.generated_scopes.is_some() {
            return "Review suggested scopes";
        }
        if self.receipt.is_none() {
            return "Prepare scope proposal draft";
        }
        if self.approved(config) {
            return "Open approved scope proposal job";
        }
        "Review plan and allowance"
    }
}

impl ShellApp {
    pub(crate) fn context_generation(&self) -> Option<&StudyContextGeneration> {
        self.router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .context_generation
            .as_ref()
    }

    pub(super) fn open_context_generation(&mut self) {
        if self.open_scope_context_generation() {
            return;
        }
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            if config.study.accounting_error.is_some() {
                super::map_allowance::restore_map_history_allowance(config);
            }
            let mut previous = config.context_generation.take().unwrap_or_default();
            previous.bind_completed_scope_reference();
            config.context_generation = Some(StudyContextGeneration {
                generation_tool: previous.generation_tool,
                context_input: brief::fresh_input(previous.context_input),
                preparation_jobs: previous.preparation_jobs,
                return_context_editor: previous.return_context_editor,
                guidance_editor: previous.guidance_editor,
                selected_text_label: previous.selected_text_label,
                ..Default::default()
            });
            config.notice = None;
        }
    }

    pub(super) fn handle_context_generation_key(&mut self, code: KeyCode) -> InputUpdate {
        if code == KeyCode::Esc && self.context_generation().is_some_and(|g| g.show_answer) {
            self.router
                .campaign_mut()
                .batch_scan_config
                .as_mut()
                .unwrap()
                .context_generation
                .as_mut()
                .unwrap()
                .show_answer = false;
            return InputUpdate::handled();
        }
        if let Some(update) = self.context_brief_key(code) {
            return update;
        }
        if self
            .context_generation()
            .is_some_and(|generation| generation.show_rejected)
        {
            return self.handle_rejected_context_key(code);
        }
        match code {
            KeyCode::Enter => return self.advance_context_generation(),
            KeyCode::Char('m') => return self.review_generated_map(),
            KeyCode::Esc => self.close_context_generation(),
            KeyCode::Char('t') => self.edit_context_allowance(BatchScanConfigRow::ProviderCalls),
            KeyCode::Char('r') => self.edit_context_allowance(BatchScanConfigRow::ReviewCalls),
            KeyCode::Char('n') if !self.has_running_work() => {
                self.open_generation_preserving_correction()
            }
            KeyCode::Char('M')
                if !self.has_running_work()
                    && self
                        .context_generation()
                        .is_some_and(|generation| generation.allows_model_choice()) =>
            {
                self.open_model_picker()
            }
            KeyCode::Tab => self.toggle_context_options(),
            KeyCode::Char('p')
                if self
                    .context_generation()
                    .is_some_and(|g| g.supports_result_overview()) =>
            {
                self.toggle_context_result_plan()
            }
            KeyCode::Char('G')
                if self.context_generation().is_some_and(|generation| {
                    generation.is_regeneration()
                        || generation.is_lesson()
                        || generation.is_question()
                        || generation.is_workflow_proposal()
                }) =>
            {
                self.edit_regeneration_guidance()
            }
            KeyCode::Char('d') => self.inspect_rejected_context(),
            KeyCode::Char('s')
                if self
                    .context_generation()
                    .is_some_and(|generation| generation.supports_rejected_retention()) =>
            {
                self.toggle_rejected_output_retention()
            }
            _ => self.scroll_context_generation(code),
        }
        InputUpdate::handled()
    }

    fn toggle_context_options(&mut self) {
        if let Some(generation) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.context_generation.as_mut())
        {
            generation.select_reader(generation.show_plan, !generation.show_options);
        }
    }

    fn toggle_context_result_plan(&mut self) {
        if let Some(generation) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.context_generation.as_mut())
        {
            generation.select_reader(!generation.show_plan || generation.show_options, false);
        }
    }

    fn review_generated_map(&mut self) -> InputUpdate {
        if self.has_running_work() {
            return InputUpdate::handled();
        }
        if let Some(update) = self.inspect_alternate_context_result() {
            return update;
        }
        if self.open_reviewed_context_map() {
            return InputUpdate::handled();
        }
        self.record_generated_context_map()
    }

    fn inspect_alternate_context_result(&mut self) -> Option<InputUpdate> {
        let generation = self.context_generation()?;
        if generation.is_lesson() {
            return Some(self.inspect_generated_lesson());
        }
        if generation.is_question() {
            return Some(self.inspect_question_answer());
        }
        if generation.is_workflow_proposal() {
            return Some(self.inspect_workflow_proposal());
        }
        self.inspect_scope_context_result()
    }

    fn inspect_scope_context_result(&mut self) -> Option<InputUpdate> {
        let generation = self.context_generation()?;
        if generation.is_scope_proposal() {
            return Some(self.inspect_generated_scopes());
        }
        if generation.is_regeneration() {
            self.set_batch_config_notice("Regenerated text is an inactive draft. Enter inspects it; d compares it with its parent. In the context browser, c checks the exact revision before Map review.");
            return Some(InputUpdate::handled());
        }
        None
    }

    fn record_generated_context_map(&mut self) -> InputUpdate {
        let Some(generation) = self.context_generation() else {
            return InputUpdate::handled();
        };
        if generation.generated.is_none() {
            self.set_batch_config_notice(
                "A completed, readable context job is required before reviewing Map.",
            );
            return InputUpdate::handled();
        }
        let Some(receipt) = generation.receipt.as_ref() else {
            return InputUpdate::handled();
        };
        let input =
            json!({"campaignId":receipt.campaign_id,"expectedPlanSha256":receipt.plan_sha256});
        self.retain_setup_context_study();
        self.dispatch_context_action("campaign:context-map", input)
    }

    fn close_context_generation(&mut self) {
        if self.keep_model_study_choices() {
            return;
        }
        if self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .is_some_and(|config| config.dfd_origin.is_some())
        {
            self.close_batch_config();
            return;
        }
        if self
            .context_generation()
            .is_some_and(|g| g.is_workflow_proposal())
        {
            self.retain_workflow_proposal();
            self.close_batch_config();
            self.set_info_notice(
                "plan",
                "Proposal draft kept. /plan reopens it without making a request.",
            );
            return;
        }
        if self.context_generation().is_some_and(|g| g.is_question()) {
            self.close_batch_config();
            return;
        }
        if self
            .context_generation()
            .is_some_and(|generation| generation.is_lesson())
        {
            self.retain_lesson_study();
            self.close_batch_config();
            return;
        }
        if self.restore_regeneration_editor() {
            return;
        }
        if self
            .context_generation()
            .is_some_and(|generation| generation.is_scope_proposal())
        {
            self.close_batch_config();
            return;
        }
        if self.retain_setup_context_study() {
            self.close_batch_config();
            return;
        }
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.context_generation = None;
            config.notice = None;
        }
    }

    fn edit_context_allowance(&mut self, row: BatchScanConfigRow) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.begin_number_edit(row);
        }
    }

    fn advance_context_generation(&mut self) -> InputUpdate {
        if self.has_running_work() {
            return InputUpdate::handled();
        }
        let Some(config) = self.router.campaign().batch_scan_config.clone() else {
            return InputUpdate::handled();
        };
        let Some(generation) = config.context_generation.as_ref() else {
            return InputUpdate::handled();
        };
        if generation.has_unsaved_guidance() {
            self.set_batch_config_notice("Your guidance draft is kept. G opens it; Ctrl+S includes it before preparing the plan.");
            return InputUpdate::handled();
        }
        self.advance_context_draft(&config, generation)
    }

    fn advance_context_draft(
        &mut self,
        config: &BatchScanConfig,
        generation: &StudyContextGeneration,
    ) -> InputUpdate {
        if generation.generated_answer.is_some() {
            return self.inspect_question_answer();
        }
        if generation.generated_proposal.is_some() {
            return self.inspect_workflow_proposal();
        }
        if generation.generated_lesson.is_some() {
            return self.inspect_generated_lesson();
        }
        if generation.generated_scopes.is_some() {
            return self.inspect_generated_scopes();
        }
        if let Some(error) = &generation.result_error {
            return self.open_context_jobs(generation, format!("Context result unavailable: {error}. Use a for context review; n prepares a separately approved replacement draft."));
        }
        if let Some(reference) = &generation.generated {
            return self.inspect_generated_context(reference.clone());
        }
        if generation.receipt.is_none() {
            return self.prepare_context_generation(&config);
        }
        if generation.approved(&config) {
            let result = generation.result_label();
            return self.open_context_jobs(
                generation,
                format!("L starts the approved jobs. After completion, a reopens {result} review."),
            );
        }
        match context_action_input(&config) {
            Ok((tool, input)) => self.dispatch_context_action(tool, input),
            Err(error) => {
                self.set_batch_config_notice(format!("{error:#}"));
                InputUpdate::handled()
            }
        }
    }

    fn prepare_context_generation(&mut self, config: &BatchScanConfig) -> InputUpdate {
        if let Err(error) = config.study.ensure_accounting_ready() {
            self.set_batch_config_notice(format!("{error:#}"));
            return InputUpdate::handled();
        }
        let id = kuzushi_core::new_run_id("context-study");
        if let Some(generation) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.context_generation.as_mut())
        {
            generation.campaign_id = Some(id.clone());
        }
        let mut input = json!({"campaignId":id,"investigationId":config.study.investigation_id,"contextInput":object_or_empty(config.context_generation.as_ref().map(|g| &g.context_input)),
            "generationTool":config.context_generation.as_ref().and_then(|g|g.generation_tool.as_deref()).unwrap_or("threat-model:build"),
            "preparationJobs":config.context_generation.as_ref().map(|g| &g.preparation_jobs).filter(|v| v.is_array()).cloned().unwrap_or_else(|| json!([]))});
        if let Err(error) = self.bind_scope_context_origin(config, &mut input) {
            self.set_batch_config_notice(format!("{error:#}"));
            return InputUpdate::handled();
        }
        super::launch::bind_brief_input(&mut input, config);
        input["useBriefGuidance"] = json!(config
            .context_generation
            .as_ref()
            .is_some_and(|generation| generation.use_brief_guidance));
        self.dispatch_context_action("campaign:context-study", input)
    }

    pub(super) fn dispatch_context_action(&mut self, tool: &str, input: Value) -> InputUpdate {
        self.set_batch_config_notice(
            "Preparing the selected context action. Activity shows its progress and outcome.",
        );
        InputUpdate::handled_with_effects(
            self.reduce_run_tool(Some(tool.into()), Some(input.to_string())),
        )
    }

    fn inspect_generated_context(&mut self, reference: ThreatModelRef) -> InputUpdate {
        let scope_id = self
            .context_generation()
            .and_then(|generation| generation.context_input.pointer("/scanScopeRef/scopeId"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.retain_setup_context_study();
        if self.study_context_picker().is_none() {
            self.open_study_context_picker();
        }
        if self.study_context_picker().is_none() {
            return InputUpdate::handled();
        }
        if let Some(picker) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.context_picker.as_mut())
        {
            if scope_id.is_some() {
                picker.scope_id = scope_id;
            }
            picker.selected = Some(reference);
            picker.preview = None;
            picker.detail_scroll = 0;
            picker.text_view = super::StudyContextTextView::Summary;
            picker.diagram = None;
            picker.diagram_visible = false;
        }
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            let generation = config.context_generation.take();
            if let Some(picker) = config.context_picker.as_mut() {
                picker.return_generation = generation.map(Box::new);
            }
        }
        self.inspect_study_context()
    }

    fn open_context_jobs(
        &mut self,
        generation: &StudyContextGeneration,
        notice: String,
    ) -> InputUpdate {
        let Some(receipt) = &generation.receipt else {
            return InputUpdate::handled();
        };
        self.retain_setup_context_study();
        self.retain_lesson_study();
        if let Some(config) = self.router.campaign().batch_scan_config.clone() {
            self.retain_dfd_study_return(&config);
        }
        self.router.campaign_mut().batch_scan_config = None;
        self.open_batch_results(&receipt.campaign_id);
        self.router.answers_mut().focus = crate::app::AnswerFocus::Workspace;
        self.set_input_mode(crate::app::InputMode::Navigate);
        self.clear_notice();
        self.router.campaign_mut().notice = Some(notice);
        InputUpdate::handled()
    }

    pub(super) fn cache_context_generation_result(&mut self, tool: &str, data: &Value) -> bool {
        let state = self.router.campaign_mut();
        if cache_generation_output(state.batch_scan_config.as_mut(), tool, data) {
            return true;
        }
        cache_generation_output(state.setup_context_study.as_mut(), tool, data)
    }

    pub(super) fn scroll_context_generation(&mut self, code: KeyCode) {
        if !matches!(code, KeyCode::PageUp | KeyCode::PageDown) {
            return;
        }
        let viewport = self.viewport();
        let body = crate::ui_view_models::context_generation::generation_body(
            viewport.columns,
            viewport.rows,
            self.context_generation().is_some_and(|generation| {
                generation.is_regeneration()
                    || generation.is_lesson()
                    || generation.supports_brief_guidance()
            }),
        );
        let count =
            crate::ui_view_models::context_generation::generation_lines(self, body.width as usize)
                .len();
        let max = count.saturating_sub(body.height as usize);
        if let Some(generation) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.context_generation.as_mut())
        {
            let current = generation.scroll.min(max);
            generation.scroll = if code == KeyCode::PageUp {
                current.saturating_sub(body.height as usize)
            } else {
                current.saturating_add(body.height as usize).min(max)
            };
        }
    }
}

fn context_action_input(config: &BatchScanConfig) -> Result<(&'static str, Value)> {
    let generation = config
        .context_generation
        .as_ref()
        .context("Open context generation first.")?;
    let receipt = generation
        .receipt
        .as_ref()
        .context("Prepare a context draft first.")?;
    let mut input = allowance_terms(&config.study, &receipt.model)?;
    input["reason"] = json!(format!("Operator reviewed the fixed {} job and its explicit preparation with the shared investigation allowance.", receipt.generation_tool));
    input["campaignId"] = json!(receipt.campaign_id);
    input["campaignPlanSha256"] = json!(receipt.plan_sha256);
    input["campaignJobs"] = json!(receipt.job_count());
    input["maxJobAttempts"] = json!(1);
    Ok(("campaign:approve-allowance", input))
}

fn cache_draft(generation: &mut StudyContextGeneration, notice: &mut Option<String>, data: &Value) {
    if data["campaignId"].as_str() != generation.campaign_id.as_deref() {
        return;
    }
    match serde_json::from_value(data.clone()) {
        Ok(receipt) => {
            generation.record_receipt(receipt);
            *notice = Some(
                "Draft ready. Review its source, model and allowance before generation.".into(),
            );
        }
        Err(error) => *notice = Some(format!("Context plan unavailable: {error}")),
    }
}

fn object_or_empty(value: Option<&Value>) -> Value {
    value
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}))
}

fn cache_generation_output(config: Option<&mut BatchScanConfig>, tool: &str, data: &Value) -> bool {
    let Some(config) = config else {
        return false;
    };
    let Some(generation) = config.context_generation.as_mut() else {
        return false;
    };
    if tool != "campaign:context-study"
        || data["campaignId"].as_str() != generation.campaign_id.as_deref()
    {
        return false;
    }
    cache_draft(generation, &mut config.notice, data);
    true
}
