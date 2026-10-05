use super::{persistence::*, work_plan::*, AllowanceApprovalV1, AllowanceCall};
use crate::SpendLimiter;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct StartedWork {
    job: ApprovedWorkItem,
    source_identity: String,
    config_sha256: String,
}

impl SpendLimiter {
    /// Claim an execution before the executor starts. Failure and cancellation
    /// consume the attempt; repeating the same run id never grants a second run.
    pub fn claim_work_attempt(&self, attempt: &WorkAttempt<'_>) -> Result<()> {
        attempt.reference.validate()?;
        super::domain::validate_identifier(attempt.run_id)?;
        let mut state = self.lock();
        let tx = state
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (revision, approval) = latest_approval(&tx, &attempt.reference.investigation_id)?
            .context("work has no approved allowance")?;
        require_revision(attempt.reference.revision, revision)?;
        let plan = approval
            .work_plan
            .context("allowance has no approved work plan")?;
        let job = validate_attempt(&plan, attempt)?;
        insert_attempt(&tx, attempt, &plan, job)?;
        tx.commit()?;
        Ok(())
    }
}

fn validate_attempt<'a>(
    plan: &'a ApprovedWorkPlanV1,
    attempt: &WorkAttempt<'_>,
) -> Result<&'a ApprovedWorkItem> {
    let job = plan.job(&attempt.reference.work_id)?;
    anyhow::ensure!(
        job.tool == attempt.tool && job.input_sha256 == attempt.input_sha256,
        "work input differs from the approved job"
    );
    anyhow::ensure!(
        plan.source_identity == attempt.source_identity,
        "source revision changed; approve a new plan"
    );
    anyhow::ensure!(
        plan.config_sha256 == attempt.config_sha256,
        "configuration changed; approve a new plan"
    );
    Ok(job)
}

fn insert_attempt(
    conn: &Connection,
    attempt: &WorkAttempt<'_>,
    plan: &ApprovedWorkPlanV1,
    job: &ApprovedWorkItem,
) -> Result<()> {
    let id = &attempt.reference.investigation_id;
    let count: u32 = conn.query_row(
        "select count(*) from investigation_work_attempts where investigation_id = ? and work_id = ?",
        params![id, job.work_id], |row| row.get(0),
    )?;
    anyhow::ensure!(
        count < job.max_attempts,
        "approved job attempt limit reached; finish and report or approve specific remaining work"
    );
    let started = StartedWork {
        job: job.clone(),
        source_identity: plan.source_identity.clone(),
        config_sha256: plan.config_sha256.clone(),
    };
    conn.execute(
        "insert into investigation_work_attempts(investigation_id, work_id, run_id, revision, plan_sha256, job_json, created_at)
         values (?, ?, ?, ?, ?, ?, ?)",
        params![id, job.work_id, attempt.run_id, attempt.reference.revision, plan.plan_sha256, serde_json::to_string(&started)?, crate::spend::unix_seconds()],
    ).context("this run already claimed an approved job attempt")?;
    Ok(())
}

pub(super) fn validate_work_call(
    conn: &Connection,
    approval: &AllowanceApprovalV1,
    call: &AllowanceCall,
) -> Result<()> {
    let Some(plan) = &approval.work_plan else {
        return Ok(());
    };
    let job = plan.job(&call.work_id)?;
    anyhow::ensure!(
        call.work == job.work_category()?,
        "approved work cannot change its category or spend protected review calls"
    );
    let exists: bool = conn.query_row(
        "select exists(select 1 from investigation_work_attempts where investigation_id = ? and work_id = ? and run_id = ? and revision = ?)",
        params![call.investigation_id, call.work_id, call.run_id, call.expected_revision], |row| row.get(0),
    )?;
    anyhow::ensure!(exists, "provider request has no admitted job attempt");
    Ok(())
}

pub(super) fn preserve_work_plan(
    conn: &Connection,
    approval: &AllowanceApprovalV1,
    previous: Option<&AllowanceApprovalV1>,
) -> Result<()> {
    if previous.is_some_and(|old| old.work_plan.is_some()) {
        anyhow::ensure!(
            approval.work_plan.is_some(),
            "a revised allowance cannot remove its finite work plan"
        );
    }
    let Some(plan) = &approval.work_plan else {
        return Ok(());
    };
    require_campaign_owner(conn, &approval.investigation_id, &plan.campaign_id)?;
    for job in &plan.jobs {
        preserve_job_identity(conn, &approval.investigation_id, plan, job)?;
    }
    Ok(())
}

fn preserve_job_identity(
    conn: &Connection,
    investigation: &str,
    plan: &ApprovedWorkPlanV1,
    job: &ApprovedWorkItem,
) -> Result<()> {
    let prior: Option<String> = conn.query_row(
        "select job_json from investigation_work_attempts where investigation_id = ? and work_id = ? limit 1",
        params![investigation, job.work_id], |row| row.get(0),
    ).optional()?;
    let Some(prior) = prior else {
        return Ok(());
    };
    let count: u32 = conn.query_row(
        "select count(*) from investigation_work_attempts where investigation_id = ? and work_id = ?",
        params![investigation, job.work_id], |row| row.get(0),
    )?;
    anyhow::ensure!(job.max_attempts >= count, "a revised work plan cannot discard consumed attempts");
    let prior: StartedWork = serde_json::from_str(&prior)?;
    anyhow::ensure!(
        prior.job.tool == job.tool && prior.job.input_sha256 == job.input_sha256,
        "a consumed work id cannot name a different job"
    );
    anyhow::ensure!(
        prior.source_identity == plan.source_identity && prior.config_sha256 == plan.config_sha256,
        "a consumed work id cannot move to another source revision or configuration"
    );
    Ok(())
}

fn require_campaign_owner(conn: &Connection, investigation: &str, campaign: &str) -> Result<()> {
    let other: bool = conn.query_row(
        "select exists(select 1 from investigation_allowance_revisions
         where investigation_id != ? and json_extract(approval_json, '$.workPlan.campaignId') = ?)",
        params![investigation, campaign], |row| row.get(0),
    )?;
    anyhow::ensure!(!other, "campaign already belongs to another investigation allowance");
    Ok(())
}
