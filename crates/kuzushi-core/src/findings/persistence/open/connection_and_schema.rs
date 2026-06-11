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
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let store = Self {
            conn: Connection::open_in_memory().context("Could not open in-memory findings DB")?,
        };
        store.init()?;
        Ok(store)
    }

    pub fn init(&self) -> Result<()> {
        configure_connection(&self.conn)?;
        create_schema(&self.conn)?;
        migrate_findings_columns(&self.conn)?;
        create_findings_indexes(&self.conn)?;
        migrate_triage_columns(&self.conn)?;
        migrate_finding_evidence_columns(&self.conn)?;
        migrate_legacy_fingerprints(&self.conn)?;
        Ok(())
    }
}

/// One-time rewrite of legacy fingerprints. The old identity hashed the
/// message with `DefaultHasher` (16 hex chars): unstable across Rust releases
/// and duplicated by LLM phrasing drift. Recompute every legacy row with the
/// stable v2 identity (32 hex chars). Rows that collapse onto an existing v2
/// fingerprint are duplicates by definition — the canonical row survives and
/// the duplicate is removed (evidence/triage/verifications cascade via FK).
fn migrate_legacy_fingerprints(conn: &Connection) -> Result<()> {
    let legacy: Vec<(i64, String, String, String, u32)> = conn
        .prepare(
            "select id, fingerprint, rule_id, file_path, start_line
               from findings where length(fingerprint) = 16",
        )?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?
        .collect::<std::result::Result<_, _>>()?;
    for (id, old_fingerprint, rule_id, file_path, start_line) in legacy {
        let new_fingerprint = fingerprint_parts(&rule_id, &file_path, start_line);
        let updated = conn.execute(
            "update or ignore findings set fingerprint = ?1 where id = ?2",
            params![new_fingerprint, id],
        )?;
        if updated == 0 {
            // unique(scan_id, fingerprint) collision: this row duplicates an
            // already-migrated finding under the v2 identity.
            conn.execute("delete from findings where id = ?1", params![id])?;
        }
        conn.execute(
            "update patch_results set fingerprint = ?1 where fingerprint = ?2",
            params![new_fingerprint, old_fingerprint],
        )?;
    }
    Ok(())
}

/// Concurrency posture for the findings DB. Scan workers, the shell, and MCP
/// servers can all touch `.kuzushi/v2/` at once: WAL lets readers coexist
/// with a writer, and the busy timeout makes a second writer wait instead of
/// failing with "database is locked". In-memory stores report
/// `journal_mode=memory` — that's expected; the pragma result is informational.
fn configure_connection(conn: &Connection) -> Result<()> {
    let _journal_mode: String = conn.query_row("pragma journal_mode = wal", [], |row| row.get(0))?;
    conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
    Ok(())
}

fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(FINDINGS_SCHEMA)?;
    Ok(())
}

fn migrate_findings_columns(conn: &Connection) -> Result<()> {
    for column in FINDING_COLUMN_MIGRATIONS {
        ensure_column(conn, "findings", column.name, column.sql)?;
    }
    Ok(())
}

fn create_findings_indexes(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "create index if not exists idx_findings_dedup_key
           on findings(scan_id, dedup_key) where dedup_key is not null;
         create index if not exists idx_findings_vuln_source
           on findings(vuln_source) where vuln_source is not null;",
    )?;
    Ok(())
}

fn migrate_triage_columns(conn: &Connection) -> Result<()> {
    ensure_column(
        conn,
        "triage",
        "cost_usd",
        "alter table triage add column cost_usd real not null default 0.0",
    )
}

// M2 §2.3: HTTP-evidence kind. Imported Burp/HAR captures store the full
// request/response as nullable text blobs on finding_evidence rows. Additive
// migration — existing rows keep request_blob and response_blob NULL.
fn migrate_finding_evidence_columns(conn: &Connection) -> Result<()> {
    ensure_column(
        conn,
        "finding_evidence",
        "request_blob",
        "alter table finding_evidence add column request_blob text",
    )?;
    ensure_column(
        conn,
        "finding_evidence",
        "response_blob",
        "alter table finding_evidence add column response_blob text",
    )
}

struct ColumnMigration {
    name: &'static str,
    sql: &'static str,
}

const FINDING_COLUMN_MIGRATIONS: &[ColumnMigration] = &[
    ColumnMigration {
        name: "actor_fingerprint",
        sql: "alter table findings add column actor_fingerprint text",
    },
    ColumnMigration {
        name: "static_proof_state",
        sql: "alter table findings add column static_proof_state text",
    },
    ColumnMigration {
        name: "vuln_source",
        sql: "alter table findings add column vuln_source text",
    },
    ColumnMigration {
        name: "dedup_key",
        sql: "alter table findings add column dedup_key text",
    },
    ColumnMigration {
        name: "suppressed",
        sql: "alter table findings add column suppressed integer not null default 0",
    },
    ColumnMigration {
        name: "snoozed_until",
        sql: "alter table findings add column snoozed_until text",
    },
    ColumnMigration {
        name: "remediation",
        sql: "alter table findings add column remediation text",
    },
    ColumnMigration {
        name: "references_json",
        sql: "alter table findings add column references_json text",
    },
];

const FINDINGS_SCHEMA: &str = r#"
pragma foreign_keys = on;

create table if not exists scan_runs (
  id text primary key,
  target text not null,
  status text not null,
  started_at text not null,
  completed_at text,
  findings_count integer not null default 0
);

create table if not exists findings (
  id integer primary key autoincrement,
  scan_id text not null references scan_runs(id) on delete cascade,
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
  suppressed integer not null default 0,
  snoozed_until text,
  remediation text,
  references_json text,
  unique(scan_id, fingerprint)
);

create table if not exists triage (
  finding_id integer primary key references findings(id) on delete cascade,
  verdict text not null,
  confidence real not null,
  rationale text not null,
  created_at text not null
);

create table if not exists finding_evidence (
  finding_id integer not null references findings(id) on delete cascade,
  ordinal integer not null,
  kind text not null,
  file_path text not null,
  line integer not null,
  snippet text not null,
  rationale text not null,
  confidence integer not null,
  request_blob text,
  response_blob text,
  primary key (finding_id, ordinal)
);
create index if not exists idx_finding_evidence_finding
  on finding_evidence(finding_id, ordinal);

create table if not exists patch_results (
  patch_run_id text primary key,
  fingerprint text not null,
  repo text not null,
  diff text,
  status text not null
    check (status in ('APPLY_FAILED','BUILD_FAILED','STILL_VULNERABLE',
                      'TESTS_FAILED','SOUND','VERIFIED','UNKNOWN')),
  iterations integer not null default 1,
  build_command text,
  test_command text,
  worktree_path text,
  cost_usd real,
  validator_log text,
  history_json text not null,
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now'))
);

create index if not exists idx_patch_results_fingerprint
  on patch_results(fingerprint, created_at desc);
create index if not exists idx_patch_results_repo_status
  on patch_results(repo, status);

create table if not exists verifications (
  id integer primary key autoincrement,
  finding_id integer not null references findings(id) on delete cascade,
  proof_level integer not null,
  proof_verdict text not null,
  backend text not null,
  language text,
  harness_path text,
  crash_evidence text,
  duration_ms integer not null default 0,
  cost_usd real not null default 0.0,
  notes_json text,
  created_at text not null
);
create index if not exists idx_verifications_finding
  on verifications(finding_id, created_at desc);
"#;
