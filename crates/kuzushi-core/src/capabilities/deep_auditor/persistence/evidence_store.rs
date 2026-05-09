use super::super::domain::EvidenceCitation;
use anyhow::{Context, Result};
use std::path::Path;

pub fn save_evidence(db_path: &Path, finding_id: i64, evidence: &[EvidenceCitation]) -> Result<()> {
    if evidence.is_empty() {
        return Ok(());
    }
    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("could not open {} for evidence", db_path.display()))?;
    conn.execute_batch(
        r#"
        create table if not exists findings_evidence (
          id          integer primary key autoincrement,
          finding_id  integer not null,
          file        text    not null,
          start_line  integer not null,
          end_line    integer not null,
          note        text,
          kind        text,
          created_at  text    not null default (datetime('now'))
        );
        create index if not exists idx_findings_evidence_finding
          on findings_evidence(finding_id);
        "#,
    )?;
    let mut stmt = conn.prepare(
        "insert into findings_evidence(finding_id, file, start_line, end_line, note, kind)
         values (?, ?, ?, ?, ?, ?)",
    )?;
    for ev in evidence {
        stmt.execute(rusqlite::params![
            finding_id,
            ev.file,
            ev.start_line,
            ev.end_line,
            ev.note,
            ev.kind
        ])?;
    }
    Ok(())
}
