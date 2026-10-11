use super::fleet_corpus_db_path;
use super::registry::FleetTarget;
use crate::findings::ingest_contract::{assign_clusters, classify};
use crate::findings::{Finding, FindingStore};
use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// One normalized corpus row. Derived from a per-target finding plus its
/// run's git provenance; never edited in place — the corpus is rebuilt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusFindingRow {
    pub target_id: String,
    pub fingerprint: String,
    pub file: String,
    pub line: u32,
    pub class: String,
    pub severity: String,
    pub cluster_id: String,
    pub revision_sha: Option<String>,
    pub branch: Option<String>,
    pub tool: String,
    pub title: String,
    /// Counted contract violations, comma-joined (`class-inferred`,
    /// `no-revision`, `no-line`). Never a reason to drop the row.
    pub quality_flags: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusReport {
    pub targets_ingested: usize,
    pub targets_skipped: Vec<String>,
    pub rows: usize,
    pub quality_flag_count: usize,
}

/// Tear down and rebuild the derived corpus from every registered target's
/// findings store. Truth stays per-target; this is a queryable projection.
pub fn rebuild_corpus(fleet_dir: &Path, targets: &[FleetTarget]) -> Result<CorpusReport> {
    std::fs::create_dir_all(fleet_dir)
        .with_context(|| format!("Could not create {}", fleet_dir.display()))?;
    let mut rows = Vec::new();
    let mut history = Vec::new();
    let mut included = Vec::new();
    let mut skipped = Vec::new();
    for target in targets {
        match target_rows(target) {
            Ok(mut target_rows) => {
                rows.append(&mut target_rows.current);
                history.append(&mut target_rows.history);
                included.push(target.id.clone());
            }
            Err(error) => skipped.push(format!("{}: {error:#}", target.id)),
        }
    }
    write_corpus(&fleet_corpus_db_path(fleet_dir), &rows, &history, &included)?;
    Ok(CorpusReport {
        targets_ingested: targets.len() - skipped.len(),
        targets_skipped: skipped,
        quality_flag_count: rows
            .iter()
            .filter(|row| !row.quality_flags.is_empty())
            .count(),
        rows: rows.len(),
    })
}

pub fn query_corpus_rows(
    fleet_dir: &Path,
    class: Option<&str>,
    severity: Option<&str>,
    limit: usize,
) -> Result<Vec<CorpusFindingRow>> {
    anyhow::ensure!(
        (1..=super::history::MAX_ROWS).contains(&limit),
        "fleet row limit must be between 1 and 10000"
    );
    let path = fleet_corpus_db_path(fleet_dir);
    anyhow::ensure!(
        path.exists(),
        "No fleet corpus yet. Run fleet:ingest first."
    );
    let conn = crate::sqlite_connection::open_read_only_file(&path)?;
    let mut statement = conn.prepare(
        "SELECT target_id, fingerprint, file, line, class, severity, cluster_id,
                revision_sha, branch, tool, title, quality_flags
         FROM corpus_findings
         WHERE (?1 IS NULL OR class = ?1) AND (?2 IS NULL OR severity = ?2)
         ORDER BY target_id, file, line LIMIT ?3",
    )?;
    let rows = statement
        .query_map(
            rusqlite::params![class, severity, limit as i64],
            corpus_row_from_sql,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("Could not query fleet corpus")?;
    Ok(rows)
}

fn corpus_row_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<CorpusFindingRow> {
    Ok(CorpusFindingRow {
        target_id: row.get(0)?,
        fingerprint: row.get(1)?,
        file: row.get(2)?,
        line: row.get::<_, i64>(3)? as u32,
        class: row.get(4)?,
        severity: row.get(5)?,
        cluster_id: row.get(6)?,
        revision_sha: row.get(7)?,
        branch: row.get(8)?,
        tool: row.get(9)?,
        title: row.get(10)?,
        quality_flags: row.get(11)?,
    })
}

struct TargetRows {
    current: Vec<CorpusFindingRow>,
    history: Vec<super::history::HistoryRow>,
}

fn target_rows(target: &FleetTarget) -> Result<TargetRows> {
    let db_path = crate::workspace::workspace_findings_db_path(&target.path);
    anyhow::ensure!(db_path.exists(), "no findings store");
    let store = FindingStore::open_read_only(&db_path)?;
    let observations =
        store.observation_history_window(super::history::MAX_ROWS, super::history::MAX_BYTES)?;
    let (findings, has_more) = store.grounding_candidate_window(super::history::MAX_ROWS)?;
    anyhow::ensure!(!has_more, "current fleet projection exceeds 10000 findings");
    let revisions = run_revisions(&target.path, &findings, &observations);
    let cluster_inputs: Vec<(String, u32)> = findings
        .iter()
        .map(|finding| (finding.file_path.clone(), finding.start_line))
        .collect();
    let cluster_ids = assign_clusters(&cluster_inputs);
    let current = findings
        .iter()
        .zip(cluster_ids)
        .map(|(finding, cluster_id)| corpus_row(target, finding, cluster_id, &revisions))
        .collect();
    let history = historical_rows(target, observations, &revisions);
    Ok(TargetRows { current, history })
}

fn historical_rows(
    target: &FleetTarget,
    observations: Vec<(u64, Finding)>,
    revisions: &BTreeMap<String, (String, Option<String>)>,
) -> Vec<super::history::HistoryRow> {
    let inputs = observations
        .iter()
        .map(|(_, finding)| (finding.file_path.clone(), finding.start_line))
        .collect::<Vec<_>>();
    observations
        .into_iter()
        .zip(assign_clusters(&inputs))
        .map(
            |((sequence, finding), cluster)| super::history::HistoryRow {
                sequence,
                finding: corpus_row(target, &finding, cluster, revisions),
            },
        )
        .collect()
}

/// run_id → (sha, branch) from persisted run summaries: the revision join
/// that makes findings SHA-addressable without a findings schema change.
fn run_revisions(
    target_path: &Path,
    current: &[Finding],
    history: &[(u64, Finding)],
) -> BTreeMap<String, (String, Option<String>)> {
    let ids = current
        .iter()
        .chain(history.iter().map(|(_, finding)| finding))
        .filter_map(|finding| finding.scan_id.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    ids.into_iter()
        .filter_map(|id| {
            let summary =
                crate::run_artifacts::load_run_summary_without_repair(target_path, id).ok()?;
            let git = summary.target_git?;
            Some((summary.run_id, (git.sha, git.branch)))
        })
        .collect()
}

fn corpus_row(
    target: &FleetTarget,
    finding: &Finding,
    cluster_id: String,
    revisions: &BTreeMap<String, (String, Option<String>)>,
) -> CorpusFindingRow {
    let classified = classify(&finding.rule_id, Some(&finding.rule_id), &finding.title);
    let revision = finding
        .scan_id
        .as_deref()
        .and_then(|scan_id| revisions.get(scan_id));
    let mut flags = Vec::new();
    if classified.inferred {
        flags.push("class-inferred");
    }
    if revision.is_none() {
        flags.push("no-revision");
    }
    if finding.start_line == 0 {
        flags.push("no-line");
    }
    CorpusFindingRow {
        target_id: target.id.clone(),
        fingerprint: finding.fingerprint.clone(),
        file: finding.file_path.clone(),
        line: finding.start_line,
        class: serde_variant_name(&classified.class),
        severity: finding.severity.as_str().to_string(),
        cluster_id,
        revision_sha: revision.map(|(sha, _)| sha.clone()),
        branch: revision.and_then(|(_, branch)| branch.clone()),
        tool: finding.tool.clone(),
        title: finding.title.clone(),
        quality_flags: flags.join(","),
    }
}

fn serde_variant_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "other".to_string())
}

const CORPUS_SCHEMA: &str = "CREATE TABLE corpus_findings (
        target_id    TEXT NOT NULL,
        fingerprint  TEXT NOT NULL,
        file         TEXT NOT NULL,
        line         INTEGER NOT NULL,
        class        TEXT NOT NULL,
        severity     TEXT NOT NULL,
        cluster_id   TEXT NOT NULL,
        revision_sha TEXT,
        branch       TEXT,
        tool         TEXT NOT NULL,
        title        TEXT NOT NULL,
        quality_flags TEXT NOT NULL,
        PRIMARY KEY (target_id, fingerprint)
    )";

/// Rebuild into a scratch file, then swap: readers never observe a
/// half-written corpus, and a crash leaves the previous corpus intact.
fn write_corpus(
    path: &Path,
    rows: &[CorpusFindingRow],
    history: &[super::history::HistoryRow],
    targets: &[String],
) -> Result<()> {
    let scratch = path.with_extension("rebuild");
    let _ = std::fs::remove_file(&scratch);
    let mut conn = Connection::open(&scratch)
        .with_context(|| format!("Could not create {}", scratch.display()))?;
    conn.execute_batch(CORPUS_SCHEMA)?;
    super::history::create_schema(&conn)?;
    insert_rows(&mut conn, rows)?;
    super::history::insert(&mut conn, history, targets)?;
    conn.close().map_err(|(_, error)| error)?;
    std::fs::rename(&scratch, path)
        .with_context(|| format!("Could not swap corpus into {}", path.display()))
}

fn insert_rows(conn: &mut Connection, rows: &[CorpusFindingRow]) -> Result<()> {
    let tx = conn.transaction()?;
    for row in rows {
        tx.execute(
            "INSERT OR REPLACE INTO corpus_findings
             (target_id, fingerprint, file, line, class, severity, cluster_id,
              revision_sha, branch, tool, title, quality_flags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                row.target_id,
                row.fingerprint,
                row.file,
                row.line as i64,
                row.class,
                row.severity,
                row.cluster_id,
                row.revision_sha,
                row.branch,
                row.tool,
                row.title,
                row.quality_flags,
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}
