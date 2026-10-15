use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowProposalResult {
    pub goal: String,
    pub phase: Option<String>,
    pub proposal: Value,
    pub model: String,
    pub run_id: String,
    pub source_identity: String,
}

impl ContextStudyReceipt {
    /// Historical reading remains available. Applying a draft requires the
    /// original source and declared capability contract to still be current.
    pub fn validate_workflow_proposal_actions(
        &self,
        root: &Path,
        registry: &ModuleRegistry,
    ) -> Result<()> {
        let result = self
            .workflow_proposal(root)?
            .context("Proposal result is not available")?;
        anyhow::ensure!(crate::incremental_index::current_workspace_resume_identity(root)? == self.source_identity,
            "Proposal source changed; inspect the historical job and prepare a new draft before applying actions");
        crate::capabilities::planner::validate_frozen_proposal(
            registry,
            &self.input,
            &result.proposal,
        )
    }

    pub fn workflow_proposal(&self, root: &Path) -> Result<Option<WorkflowProposalResult>> {
        anyhow::ensure!(
            self.generation_tool == generation::PLANNER_TOOL,
            "This job does not draft a workflow proposal"
        );
        let Some(run) = completed_context_run(root, self)? else {
            return Ok(None);
        };
        let (_, body) = crate::run_artifacts::read_run_artifact_text_bounded(
            root,
            &run,
            "result.json",
            512 * 1024,
        )?;
        let result: Value = serde_json::from_str(&body)?;
        anyhow::ensure!(
            result["status"] == "completed",
            "Proposal job did not produce an accepted shape; inspect its original result"
        );
        let data = &result["data"];
        validate_origin(self, data)?;
        Ok(Some(WorkflowProposalResult {
            goal: data["goal"]
                .as_str()
                .context("Proposal goal is missing")?
                .into(),
            phase: data["phase"].as_str().map(str::to_owned),
            proposal: data["proposal"].clone(),
            model: self.model.clone(),
            run_id: run,
            source_identity: self.source_identity.clone(),
        }))
    }
}

fn validate_origin(receipt: &ContextStudyReceipt, data: &Value) -> Result<()> {
    anyhow::ensure!(
        data["schemaVersion"] == 1 && data["model"] == receipt.model,
        "Proposal schema or model differs from its approved job"
    );
    anyhow::ensure!(
        data["goal"] == receipt.input["goal"] && data["phase"] == receipt.input["phase"],
        "Proposal goal or phase differs from the frozen input"
    );
    anyhow::ensure!(
        data["proposal"].is_object(),
        "Proposal result has no structured draft"
    );
    Ok(())
}
