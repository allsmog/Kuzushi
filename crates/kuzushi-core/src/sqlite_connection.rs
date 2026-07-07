use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::Path;
use std::time::Duration;

const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

pub(crate) fn open_file(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    let conn =
        Connection::open(path).with_context(|| format!("Could not open {}", path.display()))?;
    configure_file_connection(&conn)?;
    Ok(conn)
}

pub(crate) fn configure_file_connection(conn: &Connection) -> Result<()> {
    let _journal_mode: String = conn
        .query_row("pragma journal_mode = wal", [], |row| row.get(0))
        .context("Could not enable sqlite WAL mode")?;
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
        .context("Could not configure sqlite busy timeout")?;
    conn.execute_batch("pragma foreign_keys = on;")
        .context("Could not enable sqlite foreign keys")?;
    Ok(())
}
