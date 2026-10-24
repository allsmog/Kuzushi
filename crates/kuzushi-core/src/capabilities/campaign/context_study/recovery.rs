use super::*;
use crate::capabilities::threat_model::{
    load_exact_threat_model, load_threat_model_manifest, ThreatModelRef,
};
mod proposal;
mod question;
mod scope_failure;
pub use proposal::WorkflowProposalResult;
pub use question::ContextQuestionAnswer;

/// The authenticated output of one finished context job, without activation.
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedStudyContext {
    pub reference: ThreatModelRef,
    pub document: Value,
}

impl ContextStudyReceipt {
    pub fn generated_lesson(&self, root: &Path) -> Result<Option<crate::findings::LessonRef>> {
        anyhow::ensure!(
            self.generation_tool == generation::LESSON_TOOL,
            "This job does not generate a lesson"
        );
        let Some(run) = completed_context_run(root, self)? else {
            return Ok(None);
        };
        authenticated_lesson_result(root, self, &run).map(Some)
    }
    pub fn load_allowance(
        &self,
        root: &Path,
    ) -> Result<Option<crate::allowance::AllowanceSnapshot>> {
        super::super::study_receipt::load_investigation_allowance(root, &self.investigation_id)
    }

    /// Only an exact revision committed by this finished campaign job is a result.
    pub fn generated_context(&self, root: &Path) -> Result<Option<ThreatModelRef>> {
        Ok(self
            .generated_context_document(root)?
            .map(|output| output.reference))
    }

    pub fn generated_context_document(&self, root: &Path) -> Result<Option<GeneratedStudyContext>> {
        anyhow::ensure!(
            matches!(
                self.generation_tool.as_str(),
                TOOL | generation::REGENERATE_TOOL
            ),
            "scope proposal jobs do not create accepted Map context"
        );
        let job = context_generation_job(root, self)?;
        if super::partial_output::eligible(self, &job) {
            return super::partial_output::read(root, self, &job).map(Some);
        }
        let Some(run) = completed_job_run_id(&job)? else {
            return Ok(None);
        };
        context_revision_for_run(root, self, &run).map(Some)
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
        if !context_job_completed(job)
            .map_err(|error| scope_failure::explain(root, self, job, error))?
        {
            return Ok(None);
        }
        let run = job
            .run_id
            .as_deref()
            .context("completed scope job has no run identity")?;
        load_saved_scope_result(root, run, &self.model).map(Some)
    }
}

fn authenticated_lesson_result(
    root: &Path,
    receipt: &ContextStudyReceipt,
    run: &str,
) -> Result<crate::findings::LessonRef> {
    let (_, body) =
        crate::run_artifacts::read_run_artifact_text_bounded(root, run, "result.json", 256 * 1024)?;
    let value: Value = serde_json::from_str(&body)?;
    let reference: crate::findings::LessonRef =
        serde_json::from_value(value["data"]["lessonRef"].clone())
            .context("Completed lesson job has no exact lesson reference")?;
    let workspace = crate::WorkspaceTarget::new(root)?;
    let store = crate::FindingStore::open_read_only(workspace.findings_db_path())?;
    let record = store.finding_lesson_revision(&reference)?;
    let origin = record
        .generation
        .as_ref()
        .context("Generated lesson has no model receipt")?;
    anyhow::ensure!(
        record.author == "model" && record.state == crate::findings::LessonState::Draft,
        "Generation result must be an original model draft"
    );
    anyhow::ensure!(
        origin.model == receipt.model && origin.run_id.as_deref() == Some(run),
        "Lesson has a different generation model or run"
    );
    anyhow::ensure!(
        serde_json::to_value(&record.origin)? == receipt.input["originRef"],
        "Generated lesson has a different frozen origin"
    );
    Ok(reference)
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

fn completed_context_run(root: &Path, receipt: &ContextStudyReceipt) -> Result<Option<String>> {
    completed_job_run_id(&context_generation_job(root, receipt)?)
}

fn context_generation_job(
    root: &Path,
    receipt: &ContextStudyReceipt,
) -> Result<super::super::snapshot::CampaignJobSnapshot> {
    let snapshot = super::super::snapshot::load_campaign_snapshot(root, &receipt.campaign_id)?;
    let job = snapshot
        .jobs
        .into_iter()
        .find(|job| job.job_id == JOB)
        .context("context study has no generation job")?;
    anyhow::ensure!(
        job.tool.as_deref() == Some(receipt.generation_tool.as_str()),
        "context generation job tool changed"
    );
    Ok(job)
}

fn completed_job_run_id(
    job: &super::super::snapshot::CampaignJobSnapshot,
) -> Result<Option<String>> {
    if !context_job_completed(job)? {
        return Ok(None);
    }
    Ok(Some(
        job.run_id
            .clone()
            .context("completed context job has no run identity")?,
    ))
}

pub(super) fn context_revision_for_run(
    root: &Path,
    receipt: &ContextStudyReceipt,
    run: &str,
) -> Result<GeneratedStudyContext> {
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
    let document = load_exact_threat_model(root, &reference)?;
    validate_generated_origin(receipt, run, &document)?;
    Ok(GeneratedStudyContext {
        reference,
        document,
    })
}

pub(super) fn validate_generated_origin(
    receipt: &ContextStudyReceipt,
    run: &str,
    document: &Value,
) -> Result<()> {
    if receipt.input.get("sourcePaths").is_some() {
        return validate_file_origin(receipt, run, document);
    }
    if receipt.input.get("scanScopeRef").is_some() {
        return validate_group_origin(receipt, run, document);
    }
    if receipt.generation_tool != generation::REGENERATE_TOOL {
        return Ok(());
    }
    let origin = document
        .pointer("/provenance/regeneration")
        .context("regenerated context has no origin receipt")?;
    anyhow::ensure!(
        origin["sourceModelRef"] == receipt.input["threatModelRef"],
        "regenerated context has a different exact parent"
    );
    anyhow::ensure!(
        origin["receipt"]["model"] == receipt.model && origin["receipt"]["runId"] == run,
        "regenerated context has a different model or run"
    );
    anyhow::ensure!(
        origin["receipt"]["selectedFields"] == receipt.input["fields"],
        "regenerated context has a different field selection"
    );
    Ok(())
}

fn validate_file_origin(receipt: &ContextStudyReceipt, run: &str, document: &Value) -> Result<()> {
    let origin = document
        .pointer("/provenance/fileContext/receipt")
        .context("Evidence context has no generation receipt")?;
    anyhow::ensure!(
        origin["sourcePaths"] == receipt.input["sourcePaths"],
        "Generated context has a different evidence file selection"
    );
    anyhow::ensure!(
        origin["inheritedContextRef"] == receipt.input["inheritedContextRef"],
        "Generated context has a different inherited revision"
    );
    anyhow::ensure!(
        origin["runId"] == run && origin["model"] == receipt.model,
        "Generated context has a different model or run"
    );
    Ok(())
}

fn validate_group_origin(receipt: &ContextStudyReceipt, run: &str, document: &Value) -> Result<()> {
    let origin = document
        .pointer("/provenance/scopeContext/receipt")
        .context("File-group context has no generation receipt")?;
    anyhow::ensure!(
        origin["scopeRef"] == receipt.input["scanScopeRef"],
        "Generated context belongs to a different accepted file group"
    );
    anyhow::ensure!(
        origin["inheritedContextRef"] == receipt.input["inheritedContextRef"],
        "Generated context has a different inherited revision"
    );
    anyhow::ensure!(
        origin["runId"] == run && origin["model"] == receipt.model,
        "Generated context has a different model or run"
    );
    Ok(())
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
