//! Read dedupe inputs in one snapshot, refusing a partial or oversized pool.
use super::*;
use crate::findings::{DedupeLedgerLimits, DedupeLedgerRead};
use crate::ScanCancellation;
use rusqlite::types::ValueRef;
use std::time::Duration;

const DEDUPE_INPUT_SQL: &str = r#"
select projected.finding_json, projected.sources_json,
       exists(select 1 from stable_findings as stable
               where stable.stable_fp = coalesce(json_extract(projected.finding_json, '$.identityId'),
                    json_extract(projected.finding_json, '$.fingerprint'))
                 and stable.current_status = 'suppressed')
  from projected
 where not exists(select 1 from rekey_edges as edges
                   where edges.old_fp = coalesce(json_extract(projected.finding_json, '$.identityId'),
                         json_extract(projected.finding_json, '$.fingerprint')))
"#;

#[derive(Default)]
struct ReadUsage {
    observations: usize,
    bytes: usize,
}

impl FindingStore {
    pub(crate) fn read_dedupe_ledger(
        &self,
        limits: DedupeLedgerLimits,
        cancellation: Option<&ScanCancellation>,
    ) -> Result<DedupeLedgerRead> {
        limits.validate()?;
        self.with_projection_snapshot(|store| {
            crate::sqlite_read_control::read_with_timeout(
                &store.conn,
                cancellation,
                Duration::from_millis(limits.read_ms),
                || store.read_dedupe_inputs(limits, cancellation),
            )
        })
    }

    fn read_dedupe_inputs(
        &self,
        limits: DedupeLedgerLimits,
        cancellation: Option<&ScanCancellation>,
    ) -> Result<DedupeLedgerRead> {
        let mut usage = self.inspect_dedupe_observations(limits, cancellation)?;
        let sql = format!("with projected as ({LATEST_FINDING_PROJECTION_SQL}) {DEDUPE_INPUT_SQL}");
        let mut statement = self.conn.prepare(&sql)?;
        let mut rows = statement.query([])?;
        let mut findings = Vec::new();
        while let Some(row) = rows.next()? {
            crate::sqlite_read_control::check(cancellation)?;
            usage.inspect(row, &[0, 1], limits.max_bytes)?;
            let mut finding = row_to_v3_projected_finding(row)?;
            finding.suppressed |= row.get::<_, bool>(2)?;
            findings.push(finding);
        }
        findings.sort_by(finding_list_order);
        for finding in &mut findings {
            finding.verification = None;
            finding.observation_gap = None;
        }
        Ok(DedupeLedgerRead {
            findings,
            observations_read: usage.observations,
            encoded_bytes_read: usage.bytes,
        })
    }

    fn inspect_dedupe_observations(
        &self,
        limits: DedupeLedgerLimits,
        cancellation: Option<&ScanCancellation>,
    ) -> Result<ReadUsage> {
        let mut statement = self
            .conn
            .prepare("select finding_json from finding_observations limit ?1")?;
        let mut rows = statement.query([limits.max_observations as i64 + 1])?;
        let mut usage = ReadUsage::default();
        while let Some(row) = rows.next()? {
            crate::sqlite_read_control::check(cancellation)?;
            usage.observations += 1;
            anyhow::ensure!(usage.observations <= limits.max_observations,
                "triage:dedupe exceeds maxLedgerObservations ({}). Explicitly revise the read limit or use a smaller engagement. No candidate pool was returned.", limits.max_observations);
            usage.inspect(row, &[0], limits.max_bytes)?;
        }
        Ok(usage)
    }
}

impl ReadUsage {
    fn inspect(
        &mut self,
        row: &rusqlite::Row<'_>,
        columns: &[usize],
        max_bytes: usize,
    ) -> Result<()> {
        for &column in columns {
            let bytes = match row.get_ref(column)? {
                ValueRef::Text(bytes) | ValueRef::Blob(bytes) => bytes.len(),
                _ => 0,
            };
            self.bytes = self.bytes.saturating_add(bytes);
        }
        anyhow::ensure!(self.bytes <= max_bytes,
            "triage:dedupe exceeds maxLedgerBytes ({max_bytes}) across raw and projected text. Explicitly revise the read limit or use a smaller engagement. No candidate pool was returned.");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
