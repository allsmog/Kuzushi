use super::{SemanticCacheLimits, MAX_SEMANTIC_CACHE_ENTRY_BYTES};
use anyhow::{Context, Result};
use rusqlite::{config::DbConfig, Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use std::time::Duration;

pub(super) const DATABASE_FILE: &str = "cache-v2.sqlite";
pub(super) const BATCH_ENTRIES: usize = 64;

pub(super) fn open(root: &Path, limits: SemanticCacheLimits) -> Result<Connection> {
    reject_unsafe_files(root, limits)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(root.join(DATABASE_FILE), flags)?;
    connection.busy_timeout(Duration::from_millis(100))?;
    configure(&connection, limits)?;
    initialize(&connection)?;
    Ok(connection)
}

fn reject_unsafe_files(root: &Path, limits: SemanticCacheLimits) -> Result<()> {
    for name in [
        DATABASE_FILE.to_string(),
        format!("{DATABASE_FILE}-journal"),
    ] {
        reject_unsafe_file(&root.join(name), limits.max_bytes)?;
    }
    Ok(())
}

fn reject_unsafe_file(path: &Path, max_bytes: u64) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "cache database must be a regular file"
    );
    super::file_links::require_single_link(path, &metadata)?;
    anyhow::ensure!(
        metadata.len() <= max_bytes,
        "cache database exceeds its byte quota"
    );
    Ok(())
}

fn configure(connection: &Connection, limits: SemanticCacheLimits) -> Result<()> {
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    connection.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    connection.pragma_update(None, "journal_mode", "DELETE")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "cache_size", -2048)?;
    connection.pragma_update(None, "mmap_size", 0)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    let page_size = connection.pragma_query_value(None, "page_size", |row| unsigned(row, 0))?;
    connection.pragma_update(
        None,
        "max_page_count",
        sql_integer(limits.max_bytes / page_size)?,
    )?;
    Ok(())
}

fn initialize(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS entries (
        key TEXT PRIMARY KEY, created_at_ms INTEGER NOT NULL,
        byte_count INTEGER NOT NULL, body BLOB NOT NULL);
        CREATE INDEX IF NOT EXISTS entries_by_age ON entries(created_at_ms, key);
        CREATE TABLE IF NOT EXISTS cache_state (
        id INTEGER PRIMARY KEY CHECK (id=1), entries INTEGER NOT NULL,
        bytes INTEGER NOT NULL, legacy_shard INTEGER NOT NULL, last_prune_ms INTEGER NOT NULL);
        INSERT OR IGNORE INTO cache_state VALUES (1,0,0,0,0);",
    )?;
    Ok(())
}

pub(super) fn read(connection: &Connection, key: &str, cutoff: u64) -> Result<Option<Vec<u8>>> {
    Ok(connection
        .query_row(
            "SELECT body FROM entries WHERE key=?1 AND created_at_ms>=?2 AND length(body)<=?3",
            (
                key,
                sql_integer(cutoff)?,
                MAX_SEMANTIC_CACHE_ENTRY_BYTES as i64,
            ),
            |row| row.get(0),
        )
        .optional()?)
}

pub(super) fn totals(connection: &Connection) -> Result<(u64, u64)> {
    Ok(connection.query_row(
        "SELECT entries,bytes FROM cache_state WHERE id=1",
        [],
        |row| Ok((unsigned(row, 0)?, unsigned(row, 1)?)),
    )?)
}

pub(super) fn remove(connection: &Connection, key: &str) -> Result<u64> {
    let bytes: Option<u64> = connection
        .query_row(
            "SELECT byte_count FROM entries WHERE key=?1",
            [key],
            |row| unsigned(row, 0),
        )
        .optional()?;
    let Some(bytes) = bytes else { return Ok(0) };
    connection.execute("DELETE FROM entries WHERE key=?1", [key])?;
    connection.execute(
        "UPDATE cache_state SET entries=entries-1,bytes=bytes-?1 WHERE id=1",
        [sql_integer(bytes)?],
    )?;
    Ok(bytes)
}

pub(super) fn insert(connection: &Connection, key: &str, created: u64, body: &[u8]) -> Result<()> {
    connection.execute(
        "INSERT INTO entries VALUES (?1,?2,?3,?4)",
        (key, sql_integer(created)?, body.len() as i64, body),
    )?;
    connection.execute(
        "UPDATE cache_state SET entries=entries+1,bytes=bytes+?1 WHERE id=1",
        [body.len() as i64],
    )?;
    Ok(())
}

pub(super) fn oldest(connection: &Connection, cutoff: u64) -> Result<Vec<String>> {
    let mut statement = connection.prepare(
        "SELECT key FROM entries WHERE created_at_ms<?1 ORDER BY created_at_ms,key LIMIT ?2",
    )?;
    let keys = statement.query_map((sql_integer(cutoff)?, BATCH_ENTRIES as i64), |row| {
        row.get(0)
    })?;
    keys.collect::<std::result::Result<_, _>>()
        .context("Could not read cache eviction batch")
}

pub(super) fn has_expired(connection: &Connection, cutoff: u64) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM entries WHERE created_at_ms<?1)",
        [sql_integer(cutoff)?],
        |row| row.get(0),
    )?)
}

fn unsigned(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

pub(super) fn sql_integer(value: u64) -> Result<i64> {
    i64::try_from(value).context("cache integer exceeds SQLite range")
}
