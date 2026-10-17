//! Read a run's referenced grant separately from current investigation totals.
use super::{domain::validate_identifier, persistence::*, *};
use crate::SpendLimiter;
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunAllowanceContext {
    pub reference: AllowanceReferenceV1,
    pub approved_model: String,
    pub approved_limits: AllowanceLimits,
    pub current: AllowanceSnapshot,
    pub run_committed_calls: u32,
    pub run_unsettled_calls: u32,
}

impl SpendLimiter {
    /// Inspection only. Does not migrate a database, reserve transport or approve work.
    pub fn read_run_allowance_context(
        path: &Path,
        run_id: &str,
        reference: &AllowanceReferenceV1,
    ) -> Result<RunAllowanceContext> {
        reference.validate()?;
        validate_identifier(run_id)?;
        anyhow::ensure!(path.try_exists()?, "Investigation ledger is unavailable");
        let mut connection = crate::sqlite_connection::open_read_only_file(path)?;
        let transaction = connection.transaction()?;
        let approval = referenced_approval(&transaction, reference)?;
        let (run_committed_calls, run_unsettled_calls) =
            request_counts(&transaction, run_id, reference, &approval.model)?;
        let current = snapshot(&transaction, &reference.investigation_id)?;
        transaction.commit()?;
        Ok(RunAllowanceContext {
            reference: reference.clone(),
            approved_model: approval.model,
            approved_limits: approval.limits,
            current,
            run_committed_calls,
            run_unsettled_calls,
        })
    }
}

fn referenced_approval(
    conn: &Connection,
    reference: &AllowanceReferenceV1,
) -> Result<AllowanceApprovalV1> {
    let text: Option<String> = conn
        .query_row(
            "select approval_json from investigation_allowance_revisions
         where investigation_id=? and revision=?",
            params![reference.investigation_id, reference.revision],
            |row| row.get(0),
        )
        .optional()?;
    let text = text.context("The run's referenced allowance revision is unavailable")?;
    decode_approval(&reference.investigation_id, reference.revision, &text)
        .map(|(_, approval)| approval)
}

fn request_counts(
    conn: &Connection,
    run_id: &str,
    reference: &AllowanceReferenceV1,
    model: &str,
) -> Result<(u32, u32)> {
    let (calls, unsettled, invalid): (u32, u32, u32) = conn.query_row(
        "select count(*), coalesce(sum(settled_at is null),0), coalesce(sum(
            investigation_id is not ?1 or revision is not ?2 or
            json_extract(call_json,'$.investigationId') is not ?1 or
            json_extract(call_json,'$.expectedRevision') is not ?2 or
            json_extract(call_json,'$.model') is not ?3 or
            json_extract(call_json,'$.workId') is not ?4 or
            json_extract(call_json,'$.requestId') is not request_id),0)
         from investigation_call_reservations where json_extract(call_json,'$.runId')=?5",
        params![
            reference.investigation_id,
            reference.revision,
            model,
            reference.work_id,
            run_id
        ],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    anyhow::ensure!(
        invalid == 0,
        "Run request accounting differs from its referenced allowance"
    );
    Ok((calls, unsettled))
}

#[cfg(test)]
mod tests;
