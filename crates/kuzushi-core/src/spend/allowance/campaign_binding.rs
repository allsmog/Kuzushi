use super::{persistence::snapshot, AllowanceSnapshot};
use crate::SpendLimiter;
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

impl SpendLimiter {
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
