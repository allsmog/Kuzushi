//! Derived observation history; authoritative per-target stores stay unchanged.
use super::corpus::CorpusFindingRow;
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::Path;

pub(super) const MAX_ROWS: usize = 10_000;
pub(super) const MAX_BYTES: usize = 8 * 1024 * 1024;

pub(super) struct HistoryRow {
    pub(super) sequence: u64,
    pub(super) finding: CorpusFindingRow,
}

pub(super) fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "create table corpus_observations (
        target_id text not null, sequence integer not null, revision_sha text,
        payload_json text not null, primary key(target_id, sequence));
        create index corpus_observation_revision on corpus_observations(target_id, revision_sha);
        create table corpus_history_targets(target_id text primary key);",
    )?;
    Ok(())
}

pub(super) fn insert(conn: &mut Connection, rows: &[HistoryRow], targets: &[String]) -> Result<()> {
    let tx = conn.transaction()?;
    for target in targets {
        tx.execute(
            "insert into corpus_history_targets(target_id) values (?1)",
            [target],
        )?;
    }
    for row in rows {
        tx.execute("insert into corpus_observations(target_id, sequence, revision_sha, payload_json) values (?1, ?2, ?3, ?4)",
            params![row.finding.target_id, i64::try_from(row.sequence)?, row.finding.revision_sha, serde_json::to_string(&row.finding)?])?;
    }
    tx.commit()?;
    Ok(())
}

pub(super) fn revision_rows(
    fleet_dir: &Path,
    target: &str,
    base: &str,
    head: &str,
    max_rows: usize,
) -> Result<Vec<CorpusFindingRow>> {
    anyhow::ensure!(
        (1..=MAX_ROWS).contains(&max_rows),
        "maxRows must be between 1 and {MAX_ROWS}"
    );
    let conn =
        crate::sqlite_connection::open_read_only_file(&super::fleet_corpus_db_path(fleet_dir))?;
    require_target_history(&conn, target)?;
    let mut statement = conn.prepare(
        "select payload_json, length(cast(payload_json as blob))
        from corpus_observations where target_id = ?1 and revision_sha in (?2, ?3)
        order by sequence limit ?4",
    )?;
    let mut rows = statement.query(params![target, base, head, max_rows as i64 + 1])?;
    read_revision_rows(&mut rows, max_rows)
}

fn require_target_history(conn: &Connection, target: &str) -> Result<()> {
    let exists: bool = conn.query_row("select exists(select 1 from sqlite_master where type='table' and name='corpus_history_targets')", [], |row| row.get(0))?;
    anyhow::ensure!(
        exists,
        "Fleet corpus has no recorded observation history. Run fleet:ingest to rebuild it."
    );
    let recorded: bool = conn.query_row(
        "select exists(select 1 from corpus_history_targets where target_id=?1)",
        [target],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        recorded,
        "Observation history for target {target:?} is unavailable. Inspect fleet:ingest failures."
    );
    Ok(())
}

fn read_revision_rows(
    rows: &mut rusqlite::Rows<'_>,
    max_rows: usize,
) -> Result<Vec<CorpusFindingRow>> {
    let mut findings = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = rows.next()? {
        anyhow::ensure!(
            findings.len() < max_rows,
            "Revision comparison exceeds maxRows={max_rows}; no comparison was produced."
        );
        bytes = bytes
            .checked_add(usize::try_from(row.get::<_, i64>(1)?)?)
            .context("comparison byte count overflow")?;
        anyhow::ensure!(
            bytes <= MAX_BYTES,
            "Revision comparison exceeds {MAX_BYTES} payload bytes; no comparison was produced."
        );
        findings.push(serde_json::from_str(&row.get::<_, String>(0)?)?);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Connection) {
        let root = tempfile::tempdir().unwrap();
        let conn = Connection::open(super::super::fleet_corpus_db_path(root.path())).unwrap();
        create_schema(&conn).unwrap();
        conn.execute("insert into corpus_history_targets values ('owned')", [])
            .unwrap();
        (root, conn)
    }

    fn add(conn: &Connection, target: &str, sha: &str, sequence: i64, payload: &str) {
        conn.execute(
            "insert into corpus_observations values (?1, ?2, ?3, ?4)",
            params![target, sequence, sha, payload],
        )
        .unwrap();
    }

    fn payload() -> String {
        serde_json::to_string(&CorpusFindingRow {
            target_id: "owned".into(),
            fingerprint: "owned-policy".into(),
            file: "package.json".into(),
            line: 1,
            class: "other".into(),
            severity: "low".into(),
            cluster_id: "package.json:1".into(),
            revision_sha: Some("a".into()),
            branch: None,
            tool: "owned-policy".into(),
            title: "Owned policy observation".into(),
            quality_flags: String::new(),
        })
        .unwrap()
    }

    #[test]
    fn revision_query_is_target_scoped_and_refuses_row_overflow() {
        let (root, conn) = fixture();
        add(&conn, "owned", "a", 1, &payload());
        add(&conn, "owned", "b", 2, &payload());
        add(&conn, "other", "a", 3, "invalid unrelated payload");
        add(&conn, "owned", "unselected", 4, "invalid unrelated payload");
        assert_eq!(
            revision_rows(root.path(), "owned", "a", "b", 2)
                .unwrap()
                .len(),
            2
        );
        let error = revision_rows(root.path(), "owned", "a", "b", 1).unwrap_err();
        assert!(error.to_string().contains("no comparison was produced"));
        for limit in [0, MAX_ROWS + 1, usize::MAX] {
            assert!(revision_rows(root.path(), "owned", "a", "b", limit).is_err());
        }
    }

    #[test]
    fn legacy_and_skipped_target_history_refuse_a_comparison() {
        let (root, conn) = fixture();
        assert!(revision_rows(root.path(), "skipped", "a", "b", 2)
            .unwrap_err()
            .to_string()
            .contains("unavailable"));
        conn.execute("drop table corpus_history_targets", [])
            .unwrap();
        assert!(revision_rows(root.path(), "owned", "a", "b", 2)
            .unwrap_err()
            .to_string()
            .contains("fleet:ingest"));
    }

    #[test]
    fn malformed_or_oversized_comparison_fails_without_mutation() {
        for (value, message) in [
            ("{bad".to_string(), "key must be a string"),
            ("x".repeat(MAX_BYTES + 1), "payload bytes"),
        ] {
            let (root, conn) = fixture();
            add(&conn, "owned", "a", 1, &value);
            let error = revision_rows(root.path(), "owned", "a", "b", 2).unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
            let after: String = conn
                .query_row("select payload_json from corpus_observations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(after, value);
        }
    }
}
