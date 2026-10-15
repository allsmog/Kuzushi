//! Read a failed scope job's exact recorded cause without requesting new work.
use super::*;
use crate::capabilities::campaign::snapshot::CampaignJobSnapshot;

pub(super) fn explain(
    root: &Path,
    receipt: &ContextStudyReceipt,
    job: &CampaignJobSnapshot,
    error: anyhow::Error,
) -> anyhow::Error {
    match recorded_reason(root, receipt, job) {
        Ok(reason) => anyhow::anyhow!(
            "Scope proposal rejected: {reason}. Recorded job {} is {}.",
            job.job_id,
            job.state
        ),
        Err(diagnostic) => error.context(format!(
            "Recorded scope failure unavailable: {diagnostic:#}"
        )),
    }
}

fn recorded_reason(
    root: &Path,
    receipt: &ContextStudyReceipt,
    job: &CampaignJobSnapshot,
) -> Result<String> {
    let run = job
        .run_id
        .as_deref()
        .context("failed scope job has no run identity")?;
    let input = authenticated_json(root, run, "input.json")?;
    anyhow::ensure!(
        super::super::super::work_input_digest(&input)?
            == super::super::super::work_input_digest(&receipt.input)?,
        "failed scope input differs from its frozen job"
    );
    let result = authenticated_json(root, run, "result.json")?;
    anyhow::ensure!(
        result["status"] == "failed" && result["data"]["tool"] == receipt.generation_tool,
        "recorded result is not this scope job's failure"
    );
    let reason = result["data"]["error"]
        .as_str()
        .context("failed scope result has no reason")?;
    Ok(reason
        .chars()
        .take(1024)
        .flat_map(char::escape_debug)
        .collect())
}

fn authenticated_json(root: &Path, run: &str, leaf: &str) -> Result<Value> {
    let (_, text) =
        crate::run_artifacts::read_run_artifact_text_bounded(root, run, leaf, 512 * 1024)?;
    let reference = crate::run_artifacts::load_run_artifact_object_reference(root, run, leaf)?;
    anyhow::ensure!(
        reference.size_bytes == text.len() as u64
            && reference.hash == crate::content_store::object_hash(reference.kind, text.as_bytes()),
        "recorded scope artifact {leaf} changed since publication"
    );
    Ok(serde_json::from_str(&text)?)
}
