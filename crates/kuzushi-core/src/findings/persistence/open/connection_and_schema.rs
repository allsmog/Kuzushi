use super::*;

impl FindingStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Could not create {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("Could not open {}", path.display()))?;
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
        let ephemeral_dir = tempfile::tempdir().context("Could not create ephemeral findings DB")?;
        let path = ephemeral_dir.path().join("findings.sqlite3");
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
        create_finding_identities_schema(&self.conn)?;
        create_static_proof_history_schema(&self.conn)?;
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

fn create_finding_identities_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(FINDING_IDENTITIES_SCHEMA)?;
    Ok(())
}

fn create_static_proof_history_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(STATIC_PROOF_HISTORY_SCHEMA)?;
    Ok(())
}

const FINDINGS_SCHEMA: &str = r#"
pragma foreign_keys = on;

"#;

const FINDING_IDENTITIES_SCHEMA: &str = r#"
create table if not exists finding_identities (
  identity_id text primary key,
  target_id text not null,
  alias text not null,
  fingerprint_current text not null,
  first_seen_run_id text not null,
  created_at text not null,
  retired_at text,
  unique(target_id, alias)
);
create index if not exists idx_finding_identities_target
  on finding_identities(target_id, created_at asc);
create index if not exists idx_finding_identities_fingerprint_current
  on finding_identities(fingerprint_current);

create table if not exists finding_identity_fingerprints (
  identity_id text not null references finding_identities(identity_id) on delete cascade,
  fingerprint text not null,
  match_basis text not null,
  created_at text not null,
  primary key(identity_id, fingerprint)
);
create index if not exists idx_finding_identity_fingerprints_fingerprint
  on finding_identity_fingerprints(fingerprint);
"#;

const STATIC_PROOF_HISTORY_SCHEMA: &str = r#"
create table if not exists static_proof_history (
  id integer primary key autoincrement,
  finding_id integer not null,
  scan_id text not null,
  previous_state text,
  next_state text not null,
  source text not null,
  created_at text not null
);
create index if not exists idx_static_proof_history_finding
  on static_proof_history(finding_id, created_at asc, id asc);
"#;
