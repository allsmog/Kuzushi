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
        let snapshot = super::super::snapshot::load_campaign_snapshot(root, &self.campaign_id)?;
        let Some(job) = snapshot
            .jobs
            .iter()
            .find(|job| job.job_id == JOB && job.state == "completed")
        else {
            return Ok(None);
        };
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
