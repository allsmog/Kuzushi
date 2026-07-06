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
        };
        store.init()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let store = Self {
            conn: Connection::open_in_memory().context("Could not open in-memory findings DB")?,
            db_path: None,
            event_log_dir: None,
        };
        store.init()?;
        Ok(store)
    }

    pub fn init(&self) -> Result<()> {
        configure_connection(&self.conn)?;
        create_schema(&self.conn)?;
        crate::storage_v3::create_projection_schema(&self.conn)?;
        create_review_decisions_schema(&self.conn)?;
        create_finding_identities_schema(&self.conn)?;
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

fn create_review_decisions_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(REVIEW_DECISIONS_SCHEMA)?;
    ensure_column(
        conn,
        "review_decisions",
        "identity_id",
        "alter table review_decisions add column identity_id text",
    )?;
    Ok(())
}

const FINDINGS_SCHEMA: &str = r#"
pragma foreign_keys = on;

create table if not exists finding_projection_rows (
  id integer primary key autoincrement,
  run_id text not null,
  identity_id text,
  identity_match_tier text,
  fingerprint text not null,
  rule_id text not null,
  title text not null,
  severity text not null,
  file_path text not null,
  start_line integer not null,
  end_line integer,
  message text not null,
  tool text not null,
  actor_fingerprint text,
  static_proof_state text,
  created_at text not null,
  vuln_source text,
  dedup_key text,
  source_signature text,
  corroboration_count integer not null default 1,
  suppressed integer not null default 0,
  snoozed_until text,
  remediation text,
  references_json text,
  unique(run_id, fingerprint)
);
create index if not exists idx_finding_projection_rows_dedup_key
  on finding_projection_rows(dedup_key) where dedup_key is not null;
create index if not exists idx_finding_projection_rows_run_dedup_key
  on finding_projection_rows(run_id, dedup_key) where dedup_key is not null;
create index if not exists idx_finding_projection_rows_vuln_source
  on finding_projection_rows(vuln_source) where vuln_source is not null;
create index if not exists idx_finding_projection_rows_identity_id
  on finding_projection_rows(identity_id) where identity_id is not null;

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

const REVIEW_DECISIONS_SCHEMA: &str = r#"
create table if not exists review_decisions (
  id integer primary key autoincrement,
  finding_id integer not null,
  identity_id text,
  decision_verdict text not null,
  triage_verdict text,
  confidence real not null,
  rationale text not null,
  author text not null,
  created_at text not null
);
create index if not exists idx_review_decisions_finding
  on review_decisions(finding_id, created_at desc, id desc);
create index if not exists idx_review_decisions_identity
  on review_decisions(identity_id, created_at desc, id desc)
  where identity_id is not null;
"#;
