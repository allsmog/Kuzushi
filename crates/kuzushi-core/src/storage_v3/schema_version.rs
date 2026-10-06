//! The shared projection writer and findings reader use one initialization stamp.
use anyhow::{Context, Result};
use rusqlite::Connection;

const FINDINGS_READER_VERSION: i32 = 1;

pub(super) fn require_supported_schema(conn: &Connection) -> Result<()> {
    let current = version(conn)?;
    anyhow::ensure!(current <= FINDINGS_READER_VERSION,
        "findings DB schema version {current} is newer than supported version {FINDINGS_READER_VERSION}");
    Ok(())
}

pub(super) fn mark_initialized_schema(conn: &Connection) -> Result<()> {
    if version(conn)? == FINDINGS_READER_VERSION {
        return Ok(());
    }
    conn.pragma_update(None, "user_version", FINDINGS_READER_VERSION)
        .context("Could not record findings DB schema version")
}

pub(crate) fn require_initialized_schema(conn: &Connection) -> Result<()> {
    let current = version(conn)?;
    anyhow::ensure!(current == FINDINGS_READER_VERSION,
        "findings DB schema version {current} requires initialization at version {FINDINGS_READER_VERSION}");
    Ok(())
}

fn version(conn: &Connection) -> Result<i32> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .context("Could not read findings DB schema version")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_initialization_supports_a_read_only_findings_consumer() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("index.sqlite3");
        drop(crate::storage_v3::ProjectionDb::open(&path).unwrap());
        let bytes = std::fs::read(&path).unwrap();
        let store = crate::FindingStore::open_read_only(&path).unwrap();
        assert!(store.list_findings(1).unwrap().is_empty());
        drop(store);
        assert_eq!(bytes, std::fs::read(&path).unwrap());
    }

    #[test]
    fn a_newer_schema_is_rejected_before_projection_tables_are_written() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();
        assert!(super::super::create_projection_schema(&conn).is_err());
        let count: u32 = conn
            .query_row(
                "select count(*) from sqlite_master where type='table'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!(version(&conn).unwrap(), 2);
    }
}
