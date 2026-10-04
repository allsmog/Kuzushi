use super::{study_actions::allowance_terms, BatchScanConfig, BatchScanConfigRow};
use crate::app::{state_transitions::InputUpdate, ShellApp};
use anyhow::{Context, Result};
use crossterm::event::KeyCode;
use kuzushi_core::{capabilities::campaign::ContextStudyReceipt, ThreatModelRef};
use serde_json::{json, Value};

mod recovery;
mod setup;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct StudyContextGeneration {
    pub(crate) context_input: Value,
    pub(crate) preparation_jobs: Value,
    pub(crate) campaign_id: Option<String>,
    pub(crate) receipt: Option<ContextStudyReceipt>,
    pub(crate) generated: Option<ThreatModelRef>,
    pub(crate) result_error: Option<String>,
    pub(crate) scroll: usize,
    pub(crate) show_options: bool,
    pub(crate) options: std::sync::Arc<Vec<String>>,
}

impl StudyContextGeneration {
    pub(crate) fn preparation_count(&self) -> usize {
        self.receipt
            .as_ref()
            .map(|r| r.preparation_jobs.len())
            .unwrap_or_else(|| self.preparation_jobs.as_array().map_or(0, Vec::len))
    }
    pub(crate) fn record_receipt(&mut self, receipt: ContextStudyReceipt) {
        self.options =
            std::sync::Arc::new(crate::ui_view_models::context_generation::format_options(
                &json!({"contextInput":receipt.input,"preparationJobs":receipt.preparation_jobs}),
            ));
        self.receipt = Some(receipt);
        self.scroll = 0;
        self.show_options = false;
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
        if self.preparation_count() == 0 {
            "Open approved context job"
        } else {
            "Open approved Map jobs"
        }
    }

    pub(crate) fn action(&self, config: &BatchScanConfig) -> &'static str {
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
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            let previous = config.context_generation.take().unwrap_or_default();
            config.context_generation = Some(StudyContextGeneration {
                context_input: previous.context_input,
                preparation_jobs: previous.preparation_jobs,
                ..Default::default()
            });
            config.notice = None;
        }
    }

    pub(super) fn handle_context_generation_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Enter => return self.advance_context_generation(),
            KeyCode::Esc => self.close_context_generation(),
            KeyCode::Char('t') => self.edit_context_allowance(BatchScanConfigRow::ProviderCalls),
            KeyCode::Char('r') => self.edit_context_allowance(BatchScanConfigRow::ReviewCalls),
            KeyCode::Char('n') if !self.has_running_work() => self.open_context_generation(),
            KeyCode::Tab => self.toggle_context_options(),
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
            generation.show_options = !generation.show_options;
            generation.scroll = 0;
        }
    }

    fn close_context_generation(&mut self) {
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
        self.advance_context_draft(&config, generation)
    }

    fn advance_context_draft(
        &mut self,
        config: &BatchScanConfig,
        generation: &StudyContextGeneration,
    ) -> InputUpdate {
        if let Some(error) = &generation.result_error {
            return self.open_context_jobs(generation, format!("Context result unavailable: {error}. Inspect the completed attempt; n in context review prepares a separately approved draft."));
        }
        if let Some(reference) = &generation.generated {
            return self.inspect_generated_context(reference.clone());
        }
        if generation.receipt.is_none() {
            return self.prepare_context_generation(&config);
        }
        if generation.approved(&config) {
            return self.open_context_jobs(
                generation,
                "L starts the approved jobs. After completion, a reopens context review.".into(),
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
        let input = json!({"campaignId":id,"investigationId":config.study.investigation_id,"contextInput":object_or_empty(config.context_generation.as_ref().map(|g| &g.context_input)),
            "preparationJobs":config.context_generation.as_ref().map(|g| &g.preparation_jobs).filter(|v| v.is_array()).cloned().unwrap_or_else(|| json!([]))});
        self.dispatch_context_action("campaign:context-study", input)
    }

    fn dispatch_context_action(&mut self, tool: &str, input: Value) -> InputUpdate {
        self.set_batch_config_notice(
            "Preparing the selected context action. Activity shows its progress and outcome.",
        );
        InputUpdate::handled_with_effects(
            self.reduce_run_tool(Some(tool.into()), Some(input.to_string())),
        )
    }

    fn inspect_generated_context(&mut self, reference: ThreatModelRef) -> InputUpdate {
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
            picker.selected = Some(reference);
            picker.preview = None;
            picker.detail_scroll = 0;
            picker.raw = false;
            picker.diagram = None;
            picker.diagram_visible = false;
        }
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.context_generation = None;
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
        self.router.campaign_mut().batch_scan_config = None;
        self.open_batch_results(&receipt.campaign_id);
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

    fn scroll_context_generation(&mut self, code: KeyCode) {
        if !matches!(code, KeyCode::PageUp | KeyCode::PageDown) {
            return;
        }
        let viewport = self.viewport();
        let body = crate::ui_view_models::context_generation::generation_body(
            viewport.columns,
            viewport.rows,
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
    input["reason"] = json!("Operator reviewed the fixed context generation and preparation jobs with their shared investigation allowance.");
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
