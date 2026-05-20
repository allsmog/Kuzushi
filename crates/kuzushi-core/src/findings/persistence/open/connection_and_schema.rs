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
        self.conn.execute_batch(
            r#"
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
            "#,
        )?;
        ensure_column(
            &self.conn,
            "findings",
            "actor_fingerprint",
            "alter table findings add column actor_fingerprint text",
        )?;
        ensure_column(
            &self.conn,
            "findings",
            "static_proof_state",
            "alter table findings add column static_proof_state text",
        )?;
        ensure_column(
            &self.conn,
            "findings",
            "vuln_source",
            "alter table findings add column vuln_source text",
        )?;
        ensure_column(
            &self.conn,
            "findings",
            "dedup_key",
            "alter table findings add column dedup_key text",
        )?;
        self.conn.execute_batch(
            "create index if not exists idx_findings_dedup_key
               on findings(scan_id, dedup_key) where dedup_key is not null;
             create index if not exists idx_findings_vuln_source
               on findings(vuln_source) where vuln_source is not null;",
        )?;
        ensure_column(
            &self.conn,
            "triage",
            "cost_usd",
            "alter table triage add column cost_usd real not null default 0.0",
        )?;
        // M2 §2.3: HTTP-evidence kind. Imported Burp/HAR captures store the
        // full request/response as nullable text blobs on finding_evidence
        // rows. Additive migration — existing rows keep request_blob and
        // response_blob NULL.
        ensure_column(
            &self.conn,
            "finding_evidence",
            "request_blob",
            "alter table finding_evidence add column request_blob text",
        )?;
        ensure_column(
            &self.conn,
            "finding_evidence",
            "response_blob",
            "alter table finding_evidence add column response_blob text",
        )?;
        Ok(())
    }
}
