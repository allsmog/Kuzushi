use super::{schema, workspace_coverage_db_path};
use crate::modules::WorkflowPhase;
use crate::run_artifacts::RunTargetGitMetadata;
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;

const BASELINE_READ_LIMIT: usize = 10_000;

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

    /// Latest baseline per (scope, phase), across modes: a `sweep-skip` row
    /// advances the same coverage fact a real scan would.
    pub fn latest_baselines(&self) -> Result<Vec<BaselineRow>> {
        self.query_baselines(
            "SELECT scope_id, phase, mode, run_id, revision_sha, branch, dirty, MAX(ts)
             FROM scan_baselines GROUP BY scope_id, phase
             ORDER BY scope_id, phase",
        )
    }

    pub fn all_baselines(&self) -> Result<Vec<BaselineRow>> {
        self.query_baselines(
            "SELECT scope_id, phase, mode, run_id, revision_sha, branch, dirty, ts
             FROM scan_baselines ORDER BY scope_id, phase, ts",
        )
    }

    fn query_baselines(&self, sql: &str) -> Result<Vec<BaselineRow>> {
        let mut statement = self.conn.prepare(sql)?;
        let raw_rows = statement
            .query_map([], RawBaseline::from_row)?
            .take(BASELINE_READ_LIMIT + 1)
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not read scan baselines")?;
        anyhow::ensure!(raw_rows.len() <= BASELINE_READ_LIMIT,
            "coverage history exceeds the {BASELINE_READ_LIMIT}-row read limit; archive history before requesting recommendations");
        raw_rows
            .into_iter()
            .map(RawBaseline::into_baseline)
            .collect()
    }
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
