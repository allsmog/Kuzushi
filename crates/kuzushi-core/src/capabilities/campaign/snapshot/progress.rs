//! Recorded queue progress bound to an approved, unchanged discovery plan.
use super::*;
use crate::allowance::ApprovedWorkPlanV1;

/// Reading this snapshot starts no work and establishes no process liveness or
/// finding verdict. A queue's completed label does not select a phase result.
pub fn load_approved_scan_snapshot(root: &Path, campaign_id: &str) -> Result<CampaignSnapshot> {
    let workspace = crate::WorkspaceTarget::new(root)?;
    let report = crate::SpendLimiter::read_campaign_allowance_report(
        &workspace.findings_db_path(),
        campaign_id,
    )?
    .context("Study has no recorded approval")?;
    let work = report
        .approval
        .work_plan
        .context("Study approval has no fixed work plan")?;
    anyhow::ensure!(
        work.campaign_id == campaign_id,
        "Study approval belongs to another plan"
    );
    let plan = super::super::approved_work::read_bounded_plan(workspace.root(), campaign_id)?;
    super::super::approved_work::validate_report_plan(&plan, &work)?;
    let queue = read_queue(workspace.root(), campaign_id)?;
    validate_queue(queue.as_ref(), &work)?;
    snapshot_from_documents(
        workspace.root(),
        campaign_id,
        &plan,
        &queue.unwrap_or(Value::Null),
    )
}

fn read_queue(root: &Path, id: &str) -> Result<Option<Value>> {
    let path = campaign_queue_path(root, id);
    let body = match crate::bounded_file::read_utf8_text_within(root, &path, 4 * 1024 * 1024) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("Study queue is unreadable"),
    };
    serde_json::from_str(&body)
        .context("Study queue is malformed")
        .map(Some)
}

fn validate_queue(queue: Option<&Value>, work: &ApprovedWorkPlanV1) -> Result<()> {
    let Some(queue) = queue else {
        return Ok(());
    };
    let jobs = queue
        .get("jobs")
        .and_then(Value::as_object)
        .context("Study queue has no readable job map")?;
    if let Some(id) = queue.get("campaignId") {
        anyhow::ensure!(
            id.as_str() == Some(&work.campaign_id),
            "Study queue belongs to another plan"
        );
    }
    for (id, row) in jobs {
        work.job(&format!("{}:{id}", work.campaign_id))?;
        validate_queue_row(row)?;
    }
    Ok(())
}

fn validate_queue_row(row: &Value) -> Result<()> {
    let state = row
        .get("state")
        .and_then(Value::as_str)
        .context("Study queue job has no recorded state")?;
    anyhow::ensure!(!state.trim().is_empty(), "Study queue job state is empty");
    if let Some(run) = row.get("runId").filter(|run| !run.is_null()) {
        crate::RunId::parse(
            run.as_str()
                .context("Study queue run reference is malformed")?,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
