use super::{study_actions::allowance_terms, BatchScanConfig, BatchScanConfigRow};
use crate::app::{state_transitions::InputUpdate, PlanningRunStep, ShellApp};
use anyhow::{Context, Result};
use crossterm::event::KeyCode;
use kuzushi_core::capabilities::campaign::ReviewStudyReceipt;
use serde_json::{json, Value};

mod guided;
pub(super) mod recovery;
mod source_evidence;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReviewStudyDraft {
    pub(crate) input: Value,
    pub(crate) planning_step: Option<PlanningRunStep>,
    pub(crate) scroll: usize,
    pub(crate) show_options: bool,
    pub(crate) show_evidence: bool,
}

impl ShellApp {
    pub(crate) fn plan_review_step(&mut self, step: PlanningRunStep) -> Result<()> {
        let target = self
            .target_owned()
            .context("Select a repository before planning review")?;
        let mut config = BatchScanConfig::load_for_map_study(&target);
        config.study.ensure_accounting_ready()?;
        self.engagement.push_expanded_step_front(step.clone());
        self.engagement.pause_planning_queue();
        config.review_plan = Some(ReviewStudyDraft {
            input: step.input.clone(),
            planning_step: Some(step),
            scroll: 0,
            show_options: false,
            show_evidence: false,
        });
        config.notice=Some("Prepare exact review observations, then approve the shared allowance. The selected task stays queued until approved jobs open. No model request has started.".into());
        self.show_study_form(config);
        Ok(())
    }

    pub(crate) fn review_study_is_open(&self) -> bool {
        self.batch_config_open()
            && self
                .router
                .campaign()
                .batch_scan_config
                .as_ref()
                .is_some_and(|config| config.review_plan.is_some())
    }

    pub(super) fn handle_review_study_key(&mut self, code: KeyCode) -> InputUpdate {
        if self.study_notice_captures_escape() {
            return self.handle_review_attention(code);
        }
        if self.review_source_reader_is_open() {
            return self.handle_review_source_reader_key(code);
        }
        self.handle_review_plan_key(code)
    }

    fn handle_review_plan_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Enter => return self.advance_review_study(),
            KeyCode::Esc => return self.close_batch_config(),
            _ => self.apply_review_edit_key(code),
        }
        InputUpdate::handled()
    }

    fn review_source_reader_is_open(&self) -> bool {
        self.router
            .campaign()
            .batch_scan_config
            .as_ref()
            .and_then(|config| config.review_plan.as_ref())
            .is_some_and(|review| review.show_evidence)
    }

    fn handle_review_source_reader_key(&mut self, code: KeyCode) -> InputUpdate {
        match code {
            KeyCode::Esc => return self.close_batch_config(),
            KeyCode::Char('f') => self.open_review_source_file_picker(),
            _ => self.scroll_review_study(code),
        }
        InputUpdate::handled()
    }

    fn handle_review_attention(&mut self, code: KeyCode) -> InputUpdate {
        if code == KeyCode::Esc {
            self.clear_notice();
            self.clear_study_preparation_error();
            if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
                config.notice = None;
            }
        } else {
            self.scroll_review_study(code);
        }
        InputUpdate::handled()
    }

    fn apply_review_edit_key(&mut self, code: KeyCode) {
        if let Some(row) = review_limit_key(code) {
            self.edit_review_limit(row);
            return;
        }
        if self.has_running_work() {
            return;
        }
        self.apply_review_work_key(code);
    }

    fn apply_review_work_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('M') => self.open_model_picker(),
            KeyCode::Char('s') => self.cycle_review_strategy(),
            KeyCode::Char('n') => self.clear_review_plan(),
            KeyCode::Char('c') => self.toggle_review_context(),
            KeyCode::Char('e') => self.toggle_review_source_evidence(),
            KeyCode::Char('f') => self.open_review_source_file_picker(),
            _ => self.scroll_review_study(code),
        }
    }

    fn clear_review_plan(&mut self) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.study.invalidate_plan();
            config.notice=Some("Prepare a new review draft explicitly. Existing attempts and spending remain recorded; no work starts.".into());
        }
    }

    fn toggle_review_context(&mut self) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(review) = config.review_plan.as_mut() else {
            return;
        };
        if review.input.get("threatModelRef").is_some() {
            review
                .input
                .as_object_mut()
                .unwrap()
                .remove("threatModelRef");
        } else {
            review.input["threatModelRef"] = Value::Null;
        }
        config.study.invalidate_plan();
        config.notice=Some("Context choice changed explicitly. Prepare and review the new draft; accepted context and prior accounting remain unchanged.".into());
    }

    fn edit_review_limit(&mut self, row: BatchScanConfigRow) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.begin_number_edit(row);
        }
    }

    fn cycle_review_strategy(&mut self) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(review) = config.review_plan.as_mut() else {
            return;
        };
        review.input["strategy"] = json!(match review.input["strategy"].as_str() {
            Some("deep") => "standard",
            Some("standard") => "gate-deep",
            _ => "deep",
        });
        review.scroll = 0;
        config.study.invalidate_plan();
        config.notice=Some("Review strategy changed explicitly. Prepare and approve a new draft; prior spending stays recorded.".into());
    }

    fn scroll_review_study(&mut self, code: KeyCode) {
        let viewport = self.viewport();
        let Some(projection) = crate::ui_view_models::study_config::study_projection(self) else {
            return;
        };
        let page = usize::from(
            crate::ui_view_models::review_study::review_body_height(&projection, viewport.rows)
                .max(1),
        );
        let width = usize::from(viewport.columns.min(120).saturating_sub(4));
        let max = crate::ui_view_models::review_study::review_study_lines(
            &projection,
            self.config().model.as_deref(),
            width,
        )
        .len()
        .saturating_sub(page);
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(review) = config.review_plan.as_mut() else {
            return;
        };
        if code == KeyCode::Tab {
            review.show_options = !review.show_options;
            review.show_evidence = false;
            review.scroll = 0;
            return;
        }
        if code == KeyCode::Char('v') {
            review.show_evidence = !review.show_evidence;
            review.show_options = false;
            review.scroll = 0;
            return;
        }
        if let Some(offset) = review_page(code, review.scroll.min(max), page, max) {
            review.scroll = offset;
        }
    }

    fn advance_review_study(&mut self) -> InputUpdate {
        if self.has_running_work() {
            return InputUpdate::handled();
        }
        let Some(config) = self.router.campaign().batch_scan_config.clone() else {
            return InputUpdate::handled();
        };
        if config.study.approved() {
            return self.open_review_jobs(&config);
        }
        self.dispatch_review_action(review_action(&config, self.config().model.as_deref()))
    }

    fn dispatch_review_action(&mut self, action: Result<(&'static str, Value)>) -> InputUpdate {
        match action {
            Ok((tool, input)) => {
                if tool == "campaign:review-study" {
                    self.bind_review_draft_id(&input);
                }
                InputUpdate::handled_with_effects(
                    self.reduce_run_tool(Some(tool.into()), Some(input.to_string())),
                )
            }
            Err(error) => {
                self.set_batch_config_notice(format!("{error:#}"));
                InputUpdate::handled()
            }
        }
    }

    fn bind_review_draft_id(&mut self, input: &Value) {
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            config.study.campaign_id = input["campaignId"].as_str().map(str::to_owned);
        }
    }

    fn open_review_jobs(&mut self, config: &BatchScanConfig) -> InputUpdate {
        let Some(receipt) = config.study.review_receipt.as_ref() else {
            return InputUpdate::handled();
        };
        self.remove_replaced_review_step(config);
        let id = receipt.campaign_id.clone();
        self.router.campaign_mut().batch_scan_config = None;
        self.open_campaign_view(Some(id));
        self.router.campaign_mut().detail = true;
        self.router.campaign_mut().notice=Some("Review plan approved. L starts its one fixed job; a reopens the plan and allowance. Other selected tasks stay paused.".into());
        InputUpdate::handled()
    }

    fn remove_replaced_review_step(&mut self, config: &BatchScanConfig) {
        let Some(expected) = config
            .review_plan
            .as_ref()
            .and_then(|review| review.planning_step.as_ref())
        else {
            return;
        };
        if let Some(step) = self.engagement.pop_expanded_step() {
            if &step != expected {
                self.engagement.push_expanded_step_front(step);
            }
        }
    }
}

fn review_limit_key(code: KeyCode) -> Option<BatchScanConfigRow> {
    [
        (KeyCode::Char('t'), BatchScanConfigRow::ProviderCalls),
        (KeyCode::Char('r'), BatchScanConfigRow::ReviewCalls),
    ]
    .into_iter()
    .find(|(key, _)| *key == code)
    .map(|(_, row)| row)
}

fn review_page(code: KeyCode, current: usize, page: usize, max: usize) -> Option<usize> {
    match code {
        KeyCode::PageUp => Some(current.saturating_sub(page)),
        KeyCode::PageDown => Some(current.saturating_add(page).min(max)),
        _ => review_edge(code, max),
    }
}

fn review_edge(code: KeyCode, max: usize) -> Option<usize> {
    match code {
        KeyCode::Home => Some(0),
        KeyCode::End => Some(max),
        _ => None,
    }
}

fn review_action(config: &BatchScanConfig, model: Option<&str>) -> Result<(&'static str, Value)> {
    config.study.ensure_accounting_ready()?;
    let review = config
        .review_plan
        .as_ref()
        .context("Review draft unavailable")?;
    let Some(receipt) = config.study.review_receipt.as_ref() else {
        let id = kuzushi_core::new_run_id("review-study");
        let mut input = review.input.clone();
        if input.get("model").is_none() {
            input["model"] = json!(model.context("Select a model before preparing review")?);
        }
        return Ok((
            "campaign:review-study",
            json!({"campaignId":id,"investigationId":config.study.investigation_id,"reviewInput":input}),
        ));
    };
    let mut input = allowance_terms(&config.study, &receipt.model)?;
    input["reason"] =
        json!("Operator reviewed exact findings, review strategy and shared call limits.");
    input["campaignId"] = json!(receipt.campaign_id);
    input["campaignPlanSha256"] = json!(receipt.plan_sha256);
    input["campaignJobs"] = json!(1);
    input["maxJobAttempts"] = json!(1);
    Ok(("campaign:approve-allowance", input))
}
