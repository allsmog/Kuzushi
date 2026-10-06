//! Historical request counts. Reading never grants work or transport authority.
use super::{domain::validate_identifier, persistence::decode_approval, ApprovedWorkItem};
use crate::SpendLimiter;
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRunUsage {
    pub run_id: String,
    pub investigation_id: String,
    pub model: String,
    pub tool: String,
    pub source_identity: String,
    pub config_sha256: String,
    pub committed_calls: u32,
    pub unresolved_calls: u32,
}

#[derive(Deserialize)]
struct StartedWork {
    job: ApprovedWorkItem,
    source_identity: String,
    config_sha256: String,
}

struct RunWork {
    investigation: String,
    revision: u32,
    model: String,
    started: StartedWork,
}

type WorkRow = (String, u32, String, String, String, Option<String>);

impl SpendLimiter {
    pub fn read_run_provider_usage(path: &Path, run_id: &str) -> Result<Option<ProviderRunUsage>> {
        validate_identifier(run_id)?;
        if !path.try_exists()? {
            return Ok(None);
        }
        let mut conn = crate::sqlite_connection::open_read_only_file(path)?;
        let tx = conn.transaction()?;
        let Some(work) = read_work(&tx, run_id)? else {
            return Ok(None);
        };
        let (committed_calls, unresolved_calls) = read_usage(&tx, run_id, &work)?;
        let usage = ProviderRunUsage {
            run_id: run_id.into(),
            investigation_id: work.investigation,
            model: work.model,
            tool: work.started.job.tool,
            source_identity: work.started.source_identity,
            config_sha256: work.started.config_sha256,
            committed_calls,
            unresolved_calls,
        };
        tx.commit()?;
        Ok(Some(usage))
    }
}

fn read_work(conn: &Connection, run: &str) -> Result<Option<RunWork>> {
    let exists: bool = conn.query_row(
        "select exists(select 1 from sqlite_master where type='table' and name='investigation_work_attempts')",
        [], |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let mut statement = conn.prepare(
        "select a.investigation_id, a.revision, a.work_id, a.plan_sha256, a.job_json, r.approval_json
         from investigation_work_attempts a left join investigation_allowance_revisions r
         on r.investigation_id=a.investigation_id and r.revision=a.revision
         where a.run_id=? limit 2",
    )?;
    let rows = statement
        .query_map([run], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<WorkRow>>>()?;
    anyhow::ensure!(
        rows.len() <= 1,
        "run has multiple investigation work bindings"
    );
    rows.into_iter().next().map(validate_work).transpose()
}

fn validate_work(row: WorkRow) -> Result<RunWork> {
    let (investigation, revision, work_id, digest, started, approval) = row;
    let approval = approval.context("historical run work approval is missing")?;
    let (_, approval) = decode_approval(&investigation, revision, &approval)?;
    let plan = approval
        .work_plan
        .context("request evidence has no approved work plan")?;
    let started: StartedWork = serde_json::from_str(&started)?;
    anyhow::ensure!(
        plan.plan_sha256 == digest
            && plan.job(&work_id)? == &started.job
            && plan.source_identity == started.source_identity
            && plan.config_sha256 == started.config_sha256,
        "request evidence differs from the admitted work"
    );
    Ok(RunWork {
        investigation,
        revision,
        model: approval.model,
        started,
    })
}

fn read_usage(conn: &Connection, run: &str, work: &RunWork) -> Result<(u32, u32)> {
    let category = serde_json::to_value(work.started.job.work_category()?)?;
    let (calls, unresolved, invalid): (u32, u32, u32) = conn.query_row(
        "select count(*), coalesce(sum(settled_at is null),0), coalesce(sum(
            investigation_id is not ?1 or revision is not ?2 or
            json_extract(call_json,'$.investigationId') is not ?1 or
            json_extract(call_json,'$.expectedRevision') is not ?2 or
            json_extract(call_json,'$.model') is not ?3 or
            json_extract(call_json,'$.workId') is not ?4 or
            json_extract(call_json,'$.work') is not ?5 or
            json_extract(call_json,'$.requestId') is not request_id),0)
         from investigation_call_reservations where json_extract(call_json,'$.runId')=?6",
        params![
            work.investigation,
            work.revision,
            work.model,
            work.started.job.work_id,
            category.as_str(),
            run
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    anyhow::ensure!(
        invalid == 0,
        "provider request evidence differs from its admitted work"
    );
    Ok((calls, unresolved))
}

#[cfg(test)]
mod tests;
