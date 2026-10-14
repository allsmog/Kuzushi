use anyhow::{Context, Result};
use rusqlite::Connection;

const COVERAGE_SCHEMA_VERSION: i32 = 1;

const SCAN_BASELINES_SQL: &str = "CREATE TABLE IF NOT EXISTS scan_baselines (
        scope_id     TEXT NOT NULL,
        phase        TEXT NOT NULL,
        mode         TEXT NOT NULL,
        run_id       TEXT NOT NULL,
        revision_sha TEXT NOT NULL,
        branch       TEXT,
        dirty        INTEGER NOT NULL CHECK (dirty IN (0, 1)),
        ts           INTEGER NOT NULL CHECK (ts >= 0),
        PRIMARY KEY (scope_id, phase, mode, ts)
    )";

const LATEST_INDEX_SQL: &str = "CREATE INDEX IF NOT EXISTS scan_baselines_latest
        ON scan_baselines (scope_id, phase, ts DESC)";

pub(super) fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(&format!("{SCAN_BASELINES_SQL};{LATEST_INDEX_SQL};"))
        .context("Could not initialize coverage ledger schema")?;
    record_schema_version(conn)
}

pub(super) fn require_initialized(conn: &Connection) -> Result<()> {
    let current: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .context("Could not read coverage ledger schema version")?;
    anyhow::ensure!(current == COVERAGE_SCHEMA_VERSION,
        "coverage ledger schema version {current} is unavailable for read-only inspection; expected {COVERAGE_SCHEMA_VERSION}. Restore an initialized ledger or migrate it explicitly before reading");
    conn.prepare("SELECT scope_id, phase, mode, run_id, revision_sha, branch, dirty, ts FROM scan_baselines LIMIT 0")
        .context("Coverage ledger schema is incomplete; restore an initialized ledger before reading")?;
    Ok(())
}

fn record_schema_version(conn: &Connection) -> Result<()> {
    let current: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .context("Could not read coverage ledger schema version")?;
    anyhow::ensure!(
        current <= COVERAGE_SCHEMA_VERSION,
        "coverage ledger schema version {current} is newer than supported version {COVERAGE_SCHEMA_VERSION}"
    );
    if current == COVERAGE_SCHEMA_VERSION {
        return Ok(());
    }
    conn.pragma_update(None, "user_version", COVERAGE_SCHEMA_VERSION)
        .context("Could not record coverage ledger schema version")
}
