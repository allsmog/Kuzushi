use super::*;
use crate::capabilities::threat_model::{
    load_exact_threat_model, load_threat_model_manifest, ThreatModelRef,
};

impl ContextStudyReceipt {
    pub fn load_allowance(
        &self,
        root: &Path,
    ) -> Result<Option<crate::allowance::AllowanceSnapshot>> {
        super::super::study_receipt::load_investigation_allowance(root, &self.investigation_id)
    }

    /// Only an exact revision committed by this completed campaign job is a result.
    pub fn generated_context(&self, root: &Path) -> Result<Option<ThreatModelRef>> {
        anyhow::ensure!(
            self.generation_tool == TOOL,
            "scope proposal jobs do not create accepted Map context"
        );
        let snapshot = super::super::snapshot::load_campaign_snapshot(root, &self.campaign_id)?;
        let job = snapshot
            .jobs
            .iter()
            .find(|job| job.job_id == JOB)
            .context("context study has no generation job")?;
        if !context_job_completed(job)? {
            return Ok(None);
        }
        let run = job
            .run_id
            .as_deref()
            .context("completed context job has no run identity")?;
        let manifest = load_threat_model_manifest(root)?
            .context("completed context job has no immutable context manifest")?;
        let mut matches = revisions_for_run(manifest, run);
        anyhow::ensure!(
            !matches.is_empty(),
            "completed context job has no immutable revision for run {run}"
        );
        anyhow::ensure!(
            matches.len() == 1,
            "completed context job has ambiguous immutable revisions"
        );
        let reference = matches.remove(0);
        load_exact_threat_model(root, &reference)?;
        Ok(Some(reference))
    }

    pub fn generated_scopes(
        &self,
        root: &Path,
    ) -> Result<Option<crate::workspace::ScanScopeReview>> {
        anyhow::ensure!(
            self.generation_tool == generation::SCOPE_TOOL,
            "this job does not generate scan scopes"
        );
        let snapshot = super::super::snapshot::load_campaign_snapshot(root, &self.campaign_id)?;
        let job = snapshot
            .jobs
            .iter()
            .find(|job| job.job_id == JOB)
            .context("scope study has no generation job")?;
        anyhow::ensure!(
            job.tool.as_deref() == Some(generation::SCOPE_TOOL),
            "scope generation job tool changed"
        );
        if !context_job_completed(job)? {
            return Ok(None);
        }
        let run = job
            .run_id
            .as_deref()
            .context("completed scope job has no run identity")?;
        load_saved_scope_result(root, run, &self.model).map(Some)
    }
}

fn load_saved_scope_result(
    root: &Path,
    run: &str,
    model: &str,
) -> Result<crate::workspace::ScanScopeReview> {
    let (_, body) = crate::run_artifacts::read_run_artifact_text(root, run, "result.json")
        .require("Scope proposal result")?;
    let output: Value = serde_json::from_str(&body)?;
    let result: crate::workspace::ScanScopeReview = serde_json::from_value(output["data"].clone())?;
    let origin = result
        .record
        .generation
        .as_ref()
        .context("scope result lacks its model receipt")?;
    anyhow::ensure!(
        origin.run_id == run && origin.model == model,
        "scope result has a different run or model"
    );
    let workspace = crate::WorkspaceTarget::new(root)?;
    let saved = crate::workspace::load_scan_scope_proposal(&workspace, &result.reference)?;
    anyhow::ensure!(
        saved == result,
        "scope result disagrees with its committed immutable revision"
    );
    Ok(saved)
}

fn context_job_completed(job: &super::super::snapshot::CampaignJobSnapshot) -> Result<bool> {
    match job.state.as_str() {
        "planned" | "running" => Ok(false),
        "completed" => Ok(true),
        _ => anyhow::bail!(
            "context job {} is {}; inspect its recorded outcome ({}) before approving replacement work",
            job.job_id,
            job.state,
            job.reason.as_deref().unwrap_or("reason unavailable")
        ),
    }
}

fn revisions_for_run(
    manifest: crate::capabilities::threat_model::ThreatModelManifest,
    run: &str,
) -> Vec<ThreatModelRef> {
    let mut references = Vec::new();
    for model in manifest.models {
        for revision in model
            .revisions
            .iter()
            .filter(|revision| revision.run_id.as_deref() == Some(run))
        {
            references.push(ThreatModelRef {
                model_id: model.model_id.clone(),
                revision_id: revision.revision_id.clone(),
                sha256: revision.sha256.clone(),
            });
        }
    }
    references
}
