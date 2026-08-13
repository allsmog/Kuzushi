use super::fleet_corpus_db_path;
use super::registry::FleetTarget;
use crate::workspace::coverage_ledger::CoverageLedger;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

/// One-screen fleet scorecard: per target, what the per-target stores and
/// the derived corpus can prove — never more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetStatusReport {
    pub targets: Vec<FleetTargetStatus>,
    pub corpus_rows: usize,
    pub corpus_quality_flags: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetTargetStatus {
    pub target_id: String,
    pub path: String,
    pub reachable: bool,
    pub baseline_count: usize,
    pub last_scan_sha: Option<String>,
    pub last_scan_branch: Option<String>,
    pub last_scan_dirty: Option<bool>,
    pub critical_open: usize,
    pub high_open: usize,
    pub quality_flags: usize,
}

pub fn fleet_status(fleet_dir: &Path, targets: &[FleetTarget]) -> Result<FleetStatusReport> {
    let corpus = corpus_counts(fleet_dir)?;
    let statuses = targets
        .iter()
        .map(|target| target_status(target, &corpus))
        .collect::<Result<Vec<_>>>()?;
    Ok(FleetStatusReport {
        targets: statuses,
        corpus_rows: corpus.rows,
        corpus_quality_flags: corpus.quality_flags,
    })
}

struct CorpusCounts {
    rows: usize,
    quality_flags: usize,
    by_target: Vec<TargetCounts>,
}

struct TargetCounts {
    target_id: String,
    critical: usize,
    high: usize,
    quality_flags: usize,
}

fn corpus_counts(fleet_dir: &Path) -> Result<CorpusCounts> {
    let path = fleet_corpus_db_path(fleet_dir);
    if !path.exists() {
        return Ok(CorpusCounts {
            rows: 0,
            quality_flags: 0,
            by_target: Vec::new(),
        });
    }
    let conn = crate::sqlite_connection::open_read_only_file(&path)?;
    let mut statement = conn.prepare(
        "SELECT target_id,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END),
                SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END),
                SUM(CASE WHEN quality_flags != '' THEN 1 ELSE 0 END),
                COUNT(*)
         FROM corpus_findings GROUP BY target_id",
    )?;
    let mut by_target = Vec::new();
    let mut rows = 0usize;
    let mut quality_flags = 0usize;
    for entry in statement.query_map([], target_counts_from_sql)? {
        let (counts, total) = entry.context("Could not read corpus counts")?;
        rows += total;
        quality_flags += counts.quality_flags;
        by_target.push(counts);
    }
    Ok(CorpusCounts {
        rows,
        quality_flags,
        by_target,
    })
}

fn target_counts_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<(TargetCounts, usize)> {
    let total: i64 = row.get(4)?;
    Ok((
        TargetCounts {
            target_id: row.get(0)?,
            critical: row.get::<_, i64>(1)? as usize,
            high: row.get::<_, i64>(2)? as usize,
            quality_flags: row.get::<_, i64>(3)? as usize,
        },
        total as usize,
    ))
}

fn target_status(target: &FleetTarget, corpus: &CorpusCounts) -> Result<FleetTargetStatus> {
    let counts = corpus
        .by_target
        .iter()
        .find(|counts| counts.target_id == target.id);
    let baselines = target_baselines(target)?;
    let latest_scan = baselines
        .iter()
        .filter(|row| row.phase == crate::modules::WorkflowPhase::Scan)
        .max_by_key(|row| row.ts_unix);
    Ok(FleetTargetStatus {
        target_id: target.id.clone(),
        path: target.path.display().to_string(),
        reachable: target.path.is_dir(),
        baseline_count: baselines.len(),
        last_scan_sha: latest_scan.map(|row| row.revision.sha.clone()),
        last_scan_branch: latest_scan.and_then(|row| row.revision.branch.clone()),
        last_scan_dirty: latest_scan.map(|row| row.revision.dirty),
        critical_open: counts.map(|counts| counts.critical).unwrap_or(0),
        high_open: counts.map(|counts| counts.high).unwrap_or(0),
        quality_flags: counts.map(|counts| counts.quality_flags).unwrap_or(0),
    })
}

fn target_baselines(
    target: &FleetTarget,
) -> Result<Vec<crate::workspace::coverage_ledger::BaselineRow>> {
    let ledger = CoverageLedger::open_if_exists(&target.path)
        .map_err(|_| target_ledger_read_error(&target.id))?;
    let Some(ledger) = ledger else {
        return Ok(Vec::new());
    };
    ledger
        .latest_baselines()
        .map_err(|_| target_ledger_read_error(&target.id))
}

fn target_ledger_read_error(target_id: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "fleet:status could not read coverage ledger for target {target_id:?}"
    )
}
