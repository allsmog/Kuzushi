use super::{schema, workspace_coverage_db_path};
use crate::modules::WorkflowPhase;
use crate::run_artifacts::RunTargetGitMetadata;
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

const BASELINE_READ_LIMIT: usize = 10_000;
const BASELINE_TEXT_BYTES: usize = 8 * 1024 * 1024;

/// One receipt-backed coverage fact: `scope_id` was covered by `phase` in
/// `mode` at `revision` by run `run_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineRow {
    pub scope_id: String,
    pub phase: WorkflowPhase,
    pub mode: String,
    pub run_id: String,
    pub revision: RunTargetGitMetadata,
    pub ts_unix: i64,
}

pub struct CoverageLedger {
    conn: Connection,
}

impl CoverageLedger {
    pub fn open(target_root: &Path) -> Result<Self> {
        let path = workspace_coverage_db_path(target_root);
        let conn = crate::sqlite_connection::open_file(&path)?;
        schema::initialize(&conn)?;
        Ok(Self { conn })
    }

    pub(super) fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Read path: never creates, initializes or migrates the store.
    pub fn open_if_exists(target_root: &Path) -> Result<Option<Self>> {
        let path = workspace_coverage_db_path(target_root);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("Could not inspect coverage ledger"),
        }
        let conn = crate::sqlite_connection::open_read_only_file(&path)?;
        schema::require_initialized(&conn)?;
        Ok(Some(Self { conn }))
    }

    pub fn record_baseline(&self, row: &BaselineRow) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO scan_baselines
                 (scope_id, phase, mode, run_id, revision_sha, branch, dirty, ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    row.scope_id,
                    row.phase.word(),
                    row.mode,
                    row.run_id,
                    row.revision.sha,
                    row.revision.branch,
                    row.revision.dirty as i64,
                    row.ts_unix,
                ],
            )
            .context("Could not record scan baseline")?;
        Ok(())
    }

    /// Latest stored baseline per (scope, phase), across modes. Equal timestamps
    /// use storage order; they do not establish which scan completed first.
    pub fn latest_baselines(&self) -> Result<Vec<BaselineRow>> {
        self.latest_baselines_with_cancellation(None)
    }

    pub(crate) fn latest_baselines_with_cancellation(
        &self,
        cancellation: Option<&crate::ScanCancellation>,
    ) -> Result<Vec<BaselineRow>> {
        self.query_baselines(
            "WITH latest AS (
                 SELECT scope_id, phase, MAX(ts) AS ts
                 FROM scan_baselines GROUP BY scope_id, phase
             ), selected AS (
                 SELECT MAX(b.rowid) AS row_id FROM scan_baselines b
                 JOIN latest USING (scope_id, phase, ts)
                 GROUP BY b.scope_id, b.phase
             )
             SELECT scope_id, phase, mode, run_id, revision_sha, branch, dirty, ts
             FROM scan_baselines WHERE rowid IN (SELECT row_id FROM selected)
             ORDER BY scope_id, phase",
            cancellation,
        )
    }

    pub fn all_baselines(&self) -> Result<Vec<BaselineRow>> {
        self.query_baselines(
            "SELECT scope_id, phase, mode, run_id, revision_sha, branch, dirty, ts
             FROM scan_baselines ORDER BY scope_id, phase, ts, rowid",
            None,
        )
    }

    fn query_baselines(
        &self,
        sql: &str,
        cancellation: Option<&crate::ScanCancellation>,
    ) -> Result<Vec<BaselineRow>> {
        super::cancellation::read(&self.conn, cancellation, || self.read_baselines(sql))
    }

    fn read_baselines(&self, sql: &str) -> Result<Vec<BaselineRow>> {
        let mut statement = self.conn.prepare(sql)?;
        let mut rows = statement.query([])?;
        let mut raw_rows = Vec::new();
        let mut text_bytes = 0usize;
        while let Some(row) = rows.next().context("Could not read scan baselines")? {
            anyhow::ensure!(raw_rows.len() < BASELINE_READ_LIMIT,
                "coverage history exceeds the {BASELINE_READ_LIMIT}-row read limit; archive history before requesting recommendations");
            text_bytes = text_bytes.saturating_add(baseline_text_bytes(row)?);
            anyhow::ensure!(text_bytes <= BASELINE_TEXT_BYTES,
                "coverage history exceeds the {BASELINE_TEXT_BYTES}-byte read limit; archive oversized baseline metadata before requesting history advice");
            raw_rows.push(RawBaseline::from_row(row)?);
        }
        raw_rows
            .into_iter()
            .map(RawBaseline::into_baseline)
            .collect()
    }
}

fn baseline_text_bytes(row: &rusqlite::Row<'_>) -> Result<usize> {
    let mut bytes = 0usize;
    // The first six projected columns contain all retained text, including
    // optional branch metadata. Inspect borrowed bytes before allocating Strings.
    for index in 0..6 {
        if let rusqlite::types::ValueRef::Text(value) | rusqlite::types::ValueRef::Blob(value) =
            row.get_ref(index)?
        {
            bytes = bytes.saturating_add(value.len());
        }
    }
    Ok(bytes)
}

struct RawBaseline {
    scope_id: String,
    phase_word: String,
    mode: String,
    run_id: String,
    revision_sha: String,
    branch: Option<String>,
    dirty: i64,
    ts_unix: i64,
}

impl RawBaseline {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            scope_id: row.get(0)?,
            phase_word: row.get(1)?,
            mode: row.get(2)?,
            run_id: row.get(3)?,
            revision_sha: row.get(4)?,
            branch: row.get(5)?,
            dirty: row.get(6)?,
            ts_unix: row.get(7)?,
        })
    }

    fn into_baseline(self) -> Result<BaselineRow> {
        let phase = WorkflowPhase::parse(&self.phase_word).with_context(|| {
            format!(
                "coverage ledger row has unknown phase {:?}",
                self.phase_word
            )
        })?;
        Ok(BaselineRow {
            scope_id: self.scope_id,
            phase,
            mode: self.mode,
            run_id: self.run_id,
            revision: RunTargetGitMetadata {
                sha: self.revision_sha,
                branch: self.branch,
                dirty: self.dirty != 0,
            },
            ts_unix: self.ts_unix,
        })
    }
}
