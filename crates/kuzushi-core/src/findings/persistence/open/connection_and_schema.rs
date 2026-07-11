use super::*;

impl FindingStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let conn = crate::sqlite_connection::open_file(path)?;
        let store = Self {
            conn,
            db_path: Some(path.to_path_buf()),
            event_log_dir: path.parent().map(|parent| parent.join("log")),
            _ephemeral_dir: None,
        };
        store.init()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        // Kept as a test-facing convenience name, but backed by a temporary
        // v3 store so writes still flow through the event log and writer actor.
        let ephemeral_dir =
            tempfile::tempdir().context("Could not create ephemeral findings DB")?;
        let canonical_dir = std::fs::canonicalize(ephemeral_dir.path())
            .context("Could not canonicalize ephemeral findings DB directory")?;
        let path = canonical_dir.join("findings.sqlite3");
        let store = Self {
            conn: Connection::open(&path)
                .with_context(|| format!("Could not open {}", path.display()))?,
            db_path: Some(path.clone()),
            event_log_dir: path.parent().map(|parent| parent.join("log")),
            _ephemeral_dir: Some(ephemeral_dir),
        };
        store.init()?;
        Ok(store)
    }

    pub fn init(&self) -> Result<()> {
        configure_connection(&self.conn)?;
        create_schema(&self.conn)?;
        crate::storage_v3::create_projection_schema(&self.conn)?;
        record_schema_version(&self.conn)?;
        Ok(())
    }
}

const FINDINGS_SCHEMA_VERSION: i32 = 1;

fn record_schema_version(conn: &Connection) -> Result<()> {
    conn.pragma_update(None, "user_version", FINDINGS_SCHEMA_VERSION)
        .context("Could not record findings DB schema version")
}

/// Concurrency posture for the findings DB. Scan workers, the shell, and MCP
/// servers can all touch `.kuzushi/v3/` at once: WAL lets readers coexist
/// with a writer, and the busy timeout makes a second writer wait instead of
/// failing with "database is locked". In-memory stores report
/// `journal_mode=memory` — that's expected; the pragma result is informational.
fn configure_connection(conn: &Connection) -> Result<()> {
    let _journal_mode: String =
        conn.query_row("pragma journal_mode = wal", [], |row| row.get(0))?;
    conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
    Ok(())
}

fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(FINDINGS_SCHEMA)?;
    Ok(())
}

const FINDINGS_SCHEMA: &str = r#"
pragma foreign_keys = on;

"#;
