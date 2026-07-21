//! Negative knowledge: verifier-examined protections recorded so the next
//! scan attacks recorded guards instead of re-deriving refuted flows.
//!
//! Expiry is computed, never assumed: a guard row is keyed to the content
//! hash of its file at record time and dies the moment the file changes.
//! An unprimed pass re-finding a flow a live guard refutes is a
//! `guard-conflict` — flagged for review, trusted in neither direction.

use super::store::CoverageLedger;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardRow {
    pub file: String,
    pub line: u32,
    /// The protection itself, e.g. "bounds check dominates the memcpy".
    pub guard: String,
    /// What the guard protects, e.g. "wire length into snapshot_buf".
    pub protects: String,
    /// Verifier outcome against the guard, e.g. "bypass refuted: length is
    /// clamped in both callers".
    pub bypass_result: String,
    pub revision_sha: String,
    /// blake3 of the guarded file at record time — the expiry key.
    pub file_hash: String,
    pub ts_unix: i64,
}

const GUARDS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS guards (
        file          TEXT NOT NULL,
        line          INTEGER NOT NULL,
        guard         TEXT NOT NULL,
        protects      TEXT NOT NULL,
        bypass_result TEXT NOT NULL,
        revision_sha  TEXT NOT NULL,
        file_hash     TEXT NOT NULL,
        ts            INTEGER NOT NULL,
        PRIMARY KEY (file, line, guard)
    )";

impl CoverageLedger {
    pub fn record_guard(&self, target: &Path, row: &GuardRow) -> Result<()> {
        self.ensure_guards_schema()?;
        let file_hash = hash_target_file(target, &row.file)
            .context("guard rows require a hashable guarded file")?;
        self.connection()
            .execute(
                "INSERT OR REPLACE INTO guards
                 (file, line, guard, protects, bypass_result, revision_sha, file_hash, ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    row.file,
                    row.line as i64,
                    row.guard,
                    row.protects,
                    row.bypass_result,
                    row.revision_sha,
                    file_hash,
                    row.ts_unix,
                ],
            )
            .context("Could not record guard")?;
        Ok(())
    }

    /// Guards whose file still hashes to the recorded value. Rows whose
    /// file changed (or vanished) are expired — reported separately so the
    /// caller can show what negative knowledge just died.
    pub fn active_guards(&self, target: &Path) -> Result<(Vec<GuardRow>, usize)> {
        self.ensure_guards_schema()?;
        let mut expired = 0;
        let mut active = Vec::new();
        for row in self.all_guards()? {
            match hash_target_file(target, &row.file) {
                Some(hash) if hash == row.file_hash => active.push(row),
                _ => expired += 1,
            }
        }
        Ok((active, expired))
    }

    fn all_guards(&self) -> Result<Vec<GuardRow>> {
        let mut statement = self.connection().prepare(
            "SELECT file, line, guard, protects, bypass_result, revision_sha, file_hash, ts
             FROM guards ORDER BY file, line",
        )?;
        let rows = statement
            .query_map([], guard_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not read guards")?;
        Ok(rows)
    }

    fn ensure_guards_schema(&self) -> Result<()> {
        self.connection()
            .execute_batch(GUARDS_SCHEMA)
            .context("Could not initialize guards schema")
    }
}

fn guard_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GuardRow> {
    Ok(GuardRow {
        file: row.get(0)?,
        line: row.get::<_, i64>(1)? as u32,
        guard: row.get(2)?,
        protects: row.get(3)?,
        bypass_result: row.get(4)?,
        revision_sha: row.get(5)?,
        file_hash: row.get(6)?,
        ts_unix: row.get(7)?,
    })
}

fn hash_target_file(target: &Path, relative: &str) -> Option<String> {
    let bytes = std::fs::read(target.join(relative)).ok()?;
    Some(blake3::hash(&bytes).to_hex().to_string())
}

/// A fresh, unprimed finding landing inside a live guard's window is a
/// conflict: either the guard record is wrong or the finding is a re-derived
/// false positive. Neither is trusted; the row is flagged.
pub fn guard_conflict<'guards>(
    active_guards: &'guards [GuardRow],
    file: &str,
    line: u32,
) -> Option<&'guards GuardRow> {
    const CONFLICT_WINDOW: u32 = 15;
    active_guards.iter().find(|guard| {
        guard.file == file && guard.line.abs_diff(line) <= CONFLICT_WINDOW
    })
}
