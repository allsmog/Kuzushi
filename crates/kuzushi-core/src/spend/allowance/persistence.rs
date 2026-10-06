use super::domain::*;
use crate::runtime::{RuntimeCost, RuntimeCostReport};
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

pub(crate) fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "create table if not exists investigation_allowance_revisions (
            investigation_id text not null,
            revision integer not null check(revision > 0),
            approval_json text not null,
            created_at integer not null,
            primary key(investigation_id, revision)
         );
         create table if not exists investigation_call_reservations (
            investigation_id text not null,
            request_id text not null,
            reservation_id text not null unique,
            revision integer not null,
            call_json text not null,
            review integer not null check(review in (0, 1)),
            created_at integer not null,
            settled_at integer,
            observed_usd real check(observed_usd >= 0),
            cost_complete integer not null default 0 check(cost_complete in (0, 1)),
            primary key(investigation_id, request_id),
            foreign key(investigation_id, revision)
                references investigation_allowance_revisions(investigation_id, revision)
         );
         create table if not exists investigation_work_attempts (
            investigation_id text not null,
            work_id text not null,
            run_id text not null,
            revision integer not null,
            plan_sha256 text not null,
            job_json text not null,
            created_at integer not null,
            primary key(investigation_id, run_id),
            foreign key(investigation_id, revision)
                references investigation_allowance_revisions(investigation_id, revision)
         );",
    )?;
    Ok(())
}

pub(super) fn latest_approval(
    conn: &Connection,
    id: &str,
) -> Result<Option<(u32, AllowanceApprovalV1)>> {
    let row: Option<(u32, String)> = conn
        .query_row(
            "select revision, approval_json from investigation_allowance_revisions
         where investigation_id = ? order by revision desc limit 1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(revision, json)| decode_approval(id, revision, &json))
        .transpose()
}

pub(super) fn decode_approval(
    id: &str,
    revision: u32,
    json: &str,
) -> Result<(u32, AllowanceApprovalV1)> {
    let approval: AllowanceApprovalV1 = serde_json::from_str(json)?;
    approval.validate()?;
    anyhow::ensure!(
        approval.investigation_id == id,
        "allowance identity mismatch"
    );
    anyhow::ensure!(
        approval.expected_revision.checked_add(1) == Some(revision),
        "invalid allowance revision chain"
    );
    Ok((revision, approval))
}

pub(super) fn snapshot(conn: &Connection, id: &str) -> Result<AllowanceSnapshot> {
    let (revision, approval) =
        latest_approval(conn, id)?.ok_or_else(|| AllowanceError::NotApproved(id.to_string()))?;
    let usage = usage(conn, id)?;
    Ok(AllowanceSnapshot {
        schema_version: 1,
        investigation_id: id.to_string(),
        revision,
        model: approval.model,
        limits: approval.limits,
        committed_calls: usage.calls,
        review_calls: usage.review,
        unresolved_calls: usage.unresolved,
        cost: usage.cost()?,
        work_plan: approval.work_plan,
    })
}

pub(super) struct AllowanceUsage {
    pub(super) calls: u32,
    pub(super) review: u32,
    pub(super) unresolved: u32,
    exact: u32,
    observed: Option<f64>,
}

impl AllowanceUsage {
    fn cost(&self) -> Result<RuntimeCostReport> {
        if self.calls == self.exact {
            return RuntimeCost::from_usd(self.observed.unwrap_or(0.0), "allowance cost")
                .map(RuntimeCostReport::known);
        }
        match self.observed {
            Some(value) => RuntimeCost::from_usd(value, "allowance observed cost")
                .map(RuntimeCostReport::incomplete),
            None => Ok(RuntimeCostReport::UNAVAILABLE),
        }
    }
}

pub(super) fn usage(conn: &Connection, id: &str) -> Result<AllowanceUsage> {
    Ok(conn.query_row(
        "select count(*), coalesce(sum(review), 0),
                coalesce(sum(settled_at is null), 0), coalesce(sum(cost_complete), 0), sum(observed_usd)
         from investigation_call_reservations where investigation_id = ?",
        [id],
        |row| Ok(AllowanceUsage {
            calls: row.get(0)?, review: row.get(1)?, unresolved: row.get(2)?,
            exact: row.get(3)?, observed: row.get(4)?,
        }),
    )?)
}

pub(super) fn require_revision(expected: u32, current: u32) -> Result<()> {
    if expected != current {
        return Err(AllowanceError::StaleRevision { expected, current }.into());
    }
    Ok(())
}

pub(super) fn insert_approval(
    conn: &Connection,
    approval: &AllowanceApprovalV1,
    revision: u32,
) -> Result<()> {
    conn.execute(
        "insert into investigation_allowance_revisions(investigation_id, revision, approval_json, created_at)
         values (?, ?, ?, ?)",
        params![approval.investigation_id, revision, serde_json::to_string(approval)?, crate::spend::unix_seconds()],
    )?;
    Ok(())
}
