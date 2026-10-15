use super::{context_generation::StudyContextGeneration, BatchScanConfig};
use crate::app::{state_transitions::InputUpdate, ShellApp, WorkflowPhase};
use anyhow::{Context, Result};
use serde_json::json;

impl ShellApp {
    pub(crate) fn resume_workflow_proposal(&mut self) -> bool {
        let Some(config) = self.router.campaign().workflow_proposal_study.clone() else {
            return false;
        };
        if self.target_owned().as_ref() != Some(&config.target) || self.has_running_work() {
            return false;
        }
        self.show_study_form(config);
        true
    }

    pub(super) fn retain_workflow_proposal(&mut self) {
        self.router.campaign_mut().workflow_proposal_study =
            self.router.campaign().batch_scan_config.clone();
    }

    pub(crate) fn plan_workflow_proposal(
        &mut self,
        goal: &str,
        phase: Option<WorkflowPhase>,
    ) -> Result<()> {
        anyhow::ensure!(
            !self.has_running_work(),
            "Wait for active work before preparing another proposal; your goal is kept."
        );
        let target = self
            .target_owned()
            .context("Select a repository before planning")?;
        let model = self
            .config()
            .model
            .clone()
            .context("Select a model before planning")?;
        let mut input = json!({"goal":goal,"model":model});
        if let Some(level) = self.session_thinking_level_owned() {
            input["thinkingLevel"] = json!(level);
        }
        if let Some(phase) = phase {
            input["phase"] = serde_json::to_value(phase)?;
        }
        let mut config = BatchScanConfig::load_for_map_study(&target);
        super::map_allowance::restore_map_history_allowance(&mut config);
        config.study.ensure_accounting_ready()?;
        config.context_generation = Some(StudyContextGeneration {
            generation_tool: Some("planner:propose".into()),
            context_input: input,
            ..Default::default()
        });
        config.notice = Some("Experimental workflow proposal: review the goal, phase, model and shared allowance. One proposal request, no tools or repair loop. Preparing, approving and running this job are separate; proposed actions need another decision.".into());
        self.show_study_form(config);
        Ok(())
    }

    pub(super) fn inspect_workflow_proposal(&mut self) -> InputUpdate {
        let result = self
            .context_generation()
            .and_then(|generation| generation.generated_proposal.clone());
        let Some(result) = result else {
            return InputUpdate::handled();
        };
        let binding = self.workflow_proposal_binding();
        let proposal = binding
            .as_ref()
            .map_err(|error| anyhow::anyhow!("{error:#}"))
            .and_then(|_| parsed_proposal(&result));
        match proposal {
            Ok(proposal) => {
                self.close_batch_config();
                self.set_pending_plan(proposal);
                let (target, receipt) = binding.unwrap();
                self.engagement.bind_pending_workflow_proposal(target, receipt);
                self.log("plan", "Review the proposed changes; proposal spending did not approve these actions.");
            }
            Err(error) => self.set_batch_config_notice(format!("Proposal needs review: {error:#}. Inspect the original job; no new request was made.")),
        }
        InputUpdate::handled()
    }

    fn workflow_proposal_binding(
        &self,
    ) -> Result<(
        std::path::PathBuf,
        kuzushi_core::capabilities::campaign::ContextStudyReceipt,
    )> {
        let target = self
            .target_owned()
            .context("Proposal target is unavailable")?;
        let receipt = self
            .context_generation()
            .and_then(|generation| generation.receipt.clone())
            .context("Proposal job receipt is unavailable")?;
        receipt.validate_workflow_proposal_actions(&target, self.registry())?;
        anyhow::ensure!(
            self.config().model.as_deref() == Some(&receipt.model),
            "Selected model changed; prepare a new draft"
        );
        Ok((target, receipt))
    }
}

fn parsed_proposal(
    result: &kuzushi_core::capabilities::campaign::WorkflowProposalResult,
) -> Result<crate::app::PlanProposal> {
    let phase = result
        .phase
        .as_ref()
        .map(|phase| serde_json::from_value(json!(phase)))
        .transpose()?;
    crate::app::workers::parse_plan_json_for_phase(
        &result.goal,
        &serde_json::to_string(&result.proposal)?,
        phase,
    )
}

impl StudyContextGeneration {
    pub(super) fn workflow_proposal_action(&self, config: &BatchScanConfig) -> &'static str {
        if self.generated_proposal.is_some() {
            return "Inspect workflow proposal";
        }
        if self.result_error.is_some() {
            return "Inspect proposal job outcome";
        }
        if self.receipt.is_none() {
            return "Prepare workflow proposal";
        }
        self.workflow_proposal_approval_action(config)
    }

    fn workflow_proposal_approval_action(&self, config: &BatchScanConfig) -> &'static str {
        if self.approved(config) {
            "Open approved proposal job"
        } else {
            "Review plan and allowance"
        }
    }
}
