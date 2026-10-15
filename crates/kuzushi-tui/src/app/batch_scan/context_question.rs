use super::{context_generation::StudyContextGeneration, BatchScanConfig};
use crate::app::{state_transitions::InputUpdate, ShellApp};
use anyhow::{Context, Result};
use serde_json::json;
#[cfg(test)]
mod tests;

impl ShellApp {
    pub(crate) fn plan_context_question(&mut self, question: &str, notes: &str) -> Result<()> {
        anyhow::ensure!(
            !self.has_running_work(),
            "Wait for active work before planning a question. Your draft is kept."
        );
        let target = self
            .target_owned()
            .context("Select a repository before asking about context")?;
        let mut input = json!({"question":question,"operatorContext":notes});
        super::launch::bind_presented_map_context(self, &mut input)?;
        anyhow::ensure!(input["threatModelRef"].is_object(), "Accept a current Map context before asking. Start Map from Setup; your question is kept.");
        let mut config = BatchScanConfig::load_for_map_study(&target);
        super::map_allowance::restore_map_history_allowance(&mut config);
        config.study.ensure_accounting_ready()?;
        config.context_generation = Some(StudyContextGeneration {
            generation_tool: Some("threat-model:ask".into()),
            context_input: input,
            ..Default::default()
        });
        config.notice = Some("Review one context question, the selected model and shared allowance. Enter prepares a draft; approval and execution are separate. No request has started.".into());
        self.show_study_form(config);
        Ok(())
    }

    pub(super) fn inspect_question_answer(&mut self) -> InputUpdate {
        let Some(generation) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .and_then(|config| config.context_generation.as_mut())
        else {
            return InputUpdate::handled();
        };
        if generation.generated_answer.is_some() {
            generation.show_answer = true;
            generation.scroll = 0;
        }
        InputUpdate::handled()
    }
}

impl StudyContextGeneration {
    pub(super) fn question_action(&self, config: &BatchScanConfig) -> &'static str {
        if self.generated_answer.is_some() {
            return "Read question answer";
        }
        if self.result_error.is_some() {
            return "Inspect question job outcome";
        }
        if self.receipt.is_none() {
            return "Prepare question plan";
        }
        self.question_approval_action(config)
    }
    fn question_approval_action(&self, config: &BatchScanConfig) -> &'static str {
        if self.approved(config) {
            "Open approved question job"
        } else {
            "Review plan and allowance"
        }
    }
}
