use super::{
    persistence::{decode_approval, snapshot},
    AllowanceApprovalV1, AllowanceSnapshot,
};
use crate::SpendLimiter;
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
type ConsumedWorkReportRow = (String, u32, String, String, String);

/// Historical approval is evidence for reporting, never execution authority.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignAllowanceReport {
    pub approved_revision: u32,
    pub approval: AllowanceApprovalV1,
    #[serde(serialize_with = "serialize_report_accounting")]
    pub current_investigation: AllowanceSnapshot,
}

fn serialize_report_accounting<S: serde::Serializer>(
    snapshot: &AllowanceSnapshot,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    use serde::Serialize;
    let mut value = serde_json::to_value(snapshot).map_err(serde::ser::Error::custom)?;
    // Report metadata is not an execution snapshot. Unavailable money has no
    // numeric observed value, even though the accounting wire keeps a sentinel.
    if snapshot.cost.is_unavailable() {
        value["cost"]["observedUsd"] = serde_json::Value::Null;
    }
    value.serialize(serializer)
}

impl SpendLimiter {
    /// Locate a historical study by its consumed work record. This cannot
    /// approve another attempt or attach an allowance to a request.
    pub fn read_run_campaign_report(path: &Path, run_id: &str) -> Result<Option<String>> {
        if !path.try_exists()? {
            return Ok(None);
        }
        let conn = crate::sqlite_connection::open_read_only_file(path)?;
        if !work_table_exists(&conn)? {
            return Ok(None);
        }
        let mut statement = conn.prepare(
            "select a.investigation_id, a.revision, r.approval_json, a.work_id, a.plan_sha256
             from investigation_work_attempts a join investigation_allowance_revisions r
             on r.investigation_id = a.investigation_id and r.revision = a.revision
             where a.run_id = ? limit 2",
        )?;
        let rows = statement
            .query_map([run_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<ConsumedWorkReportRow>>>()?;
        anyhow::ensure!(
            rows.len() <= 1,
            "Scan run has multiple investigation work bindings"
        );
        rows.into_iter()
            .next()
            .map(campaign_from_work_record)
            .transpose()
            .map(Option::flatten)
    }

    pub fn read_campaign_allowance_report(
        path: &Path,
        campaign: &str,
    ) -> Result<Option<CampaignAllowanceReport>> {
        if !path.try_exists()? {
            return Ok(None);
        }
        let mut conn = crate::sqlite_connection::open_read_only_file(path)?;
        let tx = conn.transaction()?;
        let Some(id) = campaign_investigation(&tx, campaign)? else {
            return Ok(None);
        };
        let (revision, json) = campaign_approval(&tx, &id, campaign)?
            .context("campaign approval history is missing")?;
        let (_, approval) = decode_approval(&id, revision, &json)?;
        let report = CampaignAllowanceReport {
            approved_revision: revision,
            approval,
            current_investigation: snapshot(&tx, &id)?,
        };
        tx.commit()?;
        Ok(Some(report))
    }

    /// A campaign that was bound once must never silently fall back to legacy
    /// execution if a later allowance revision selects different work.
    pub fn read_campaign_allowance(
        path: &Path,
        campaign: &str,
    ) -> Result<Option<AllowanceSnapshot>> {
        if !path.try_exists()? {
            return Ok(None);
        }
        let mut conn = crate::sqlite_connection::open_read_only_file(path)?;
        let tx = conn.transaction()?;
        let Some(id) = campaign_investigation(&tx, campaign)? else {
            return Ok(None);
        };
        let snapshot = snapshot(&tx, &id)?;
        let plan = snapshot
            .work_plan
            .as_ref()
            .context("campaign lost its finite work approval")?;
        anyhow::ensure!(
            plan.campaign_id == campaign,
            "allowance now approves different campaign work; review this campaign separately"
        );
        tx.commit()?;
        Ok(Some(snapshot))
    }
}

fn work_table_exists(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row("select exists(select 1 from sqlite_master where type = 'table' and name = 'investigation_work_attempts')", [], |row| row.get(0))?)
}

fn campaign_from_work_record(row: ConsumedWorkReportRow) -> Result<Option<String>> {
    let (id, revision, json, work_id, digest) = row;
    let (_, approval) = decode_approval(&id, revision, &json)?;
    let plan = approval
        .work_plan
        .context("consumed study work has no approval")?;
    anyhow::ensure!(
        plan.plan_sha256 == digest,
        "consumed study work digest differs from its approval"
    );
    Ok((plan.job(&work_id)?.tool == "sast:scan").then_some(plan.campaign_id))
}

fn campaign_approval(conn: &Connection, id: &str, campaign: &str) -> Result<Option<(u32, String)>> {
    Ok(conn
        .query_row(
            "select revision, approval_json from investigation_allowance_revisions
         where investigation_id = ? and json_extract(approval_json, '$.workPlan.campaignId') = ?
         order by revision desc limit 1",
            [id, campaign],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?)
}

fn campaign_investigation(conn: &Connection, campaign: &str) -> Result<Option<String>> {
    let exists: bool = conn.query_row(
        "select exists(select 1 from sqlite_master where type = 'table' and name = 'investigation_allowance_revisions')",
        [], |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let mut statement = conn.prepare(
        "select distinct investigation_id from investigation_allowance_revisions
         where json_extract(approval_json, '$.workPlan.campaignId') = ? limit 2",
    )?;
    let ids = statement
        .query_map([campaign], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    anyhow::ensure!(ids.len() <= 1, "campaign is bound to multiple investigation allowances; select and revise its approval explicitly");
    Ok(ids.into_iter().next())
}

#[cfg(test)]
mod tests;
