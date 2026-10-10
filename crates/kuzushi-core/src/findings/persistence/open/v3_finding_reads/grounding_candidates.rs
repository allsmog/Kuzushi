//! Bound grounding's hydrated corpus window before source inspection.
use super::*;

impl FindingStore {
    pub(crate) fn grounding_candidate_window(&self, limit: usize) -> Result<(Vec<Finding>, bool)> {
        let sql = format!("{LATEST_FINDING_PROJECTION_SQL} order by latest.stable_key limit ?1");
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(
            [limit.saturating_add(1) as i64],
            row_to_v3_projected_finding,
        )?;
        let mut findings = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not read bounded citation candidates")?;
        let has_more = findings.len() > limit;
        findings.truncate(limit);
        Ok((self.hydrate_v3_findings(findings)?, has_more))
    }
}
