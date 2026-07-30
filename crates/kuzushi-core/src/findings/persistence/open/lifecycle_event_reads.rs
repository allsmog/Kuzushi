//! Reads over the projected `finding_events` lifecycle ledger.

use super::*;
use std::collections::BTreeSet;

impl FindingStore {
    /// Stable keys whose `FindingReopened` event was recorded against the
    /// given run — i.e. findings the reconciler had marked stale that this
    /// run's observations brought back.
    pub(crate) fn reopened_stable_fps_for_run(&self, run_id: &str) -> Result<BTreeSet<String>> {
        let mut stmt = self.conn.prepare(
            r#"
            select distinct stable_fp
              from finding_events
             where event_kind = 'finding-reopened'
               and stable_fp is not null
               and json_extract(payload_json, '$.reconciledAgainstRunId') = ?1
            "#,
        )?;
        let rows = stmt.query_map(params![run_id], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<BTreeSet<_>>>()
            .context("Could not list reopened findings for run")
    }
}
