//! Reads over the projected `finding_events` lifecycle ledger.

use super::*;
use std::collections::{BTreeMap, BTreeSet};

impl FindingStore {
    pub(super) fn current_observation_gaps_for(
        &self,
        stable_fps: &[String],
    ) -> Result<BTreeMap<String, FindingObservationGap>> {
        let mut stmt = self.conn.prepare(
            r#"
            select stable.stable_fp, events.seq, events.event_hash,
                   json_extract(events.payload_json, '$.lastSeenRunId'),
                   json_extract(events.payload_json, '$.reconciledAgainstRunId')
              from stable_findings as stable
              join finding_events as events on events.seq = (
                   select max(seq) from finding_events
                    where stable_fp = stable.stable_fp
                      and event_kind in ('finding-disappeared', 'finding-reopened')
              )
             where stable.stable_fp in (select value from json_each(?1))
               and events.seq > stable.last_seen_seq
               and events.event_kind = 'finding-disappeared'
            "#,
        )?;
        let rows = stmt.query_map(params![serde_json::to_string(stable_fps)?], |row| {
            Ok((row.get(0)?, FindingObservationGap {
                event_seq: row.get::<_, i64>(1)?.try_into().map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(1, rusqlite::types::Type::Integer, Box::new(error))
                })?, event_hash: row.get(2)?,
                last_seen_run_id: row.get(3)?, compared_run_id: row.get(4)?,
            }))
        })?;
        rows.collect::<rusqlite::Result<BTreeMap<_, _>>>()
            .context("Could not read finding observation gaps")
    }

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
