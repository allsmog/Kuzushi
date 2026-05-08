use super::prelude::*;
use super::*;

pub(crate) fn row_to_patch_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<PatchResult> {
    let status: String = row.get(4)?;
    let history_json: String = row.get(11)?;
    let history = serde_json::from_str::<Vec<PatchAttempt>>(&history_json)
        .map_err(|error| to_sql_error(anyhow::Error::new(error)))?;

    Ok(PatchResult {
        patch_run_id: row.get(0)?,
        fingerprint: row.get(1)?,
        repo: row.get(2)?,
        diff: row.get(3)?,
        status: PatchStatus::try_from(status.as_str()).map_err(to_sql_error)?,
        iterations: row.get::<_, i64>(5)? as usize,
        build_command: row.get(6)?,
        test_command: row.get(7)?,
        worktree_path: row.get(8)?,
        cost_usd: row.get(9)?,
        validator_log: row.get(10)?,
        history,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

pub(crate) fn row_to_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    let severity: String = row.get(5)?;
    let static_proof_state: Option<String> = row.get(12)?;
    let verdict: Option<String> = row.get(14)?;
    let triage = match verdict {
        Some(verdict) => Some(TriageOutcome {
            verdict: TriageVerdict::try_from(verdict.as_str()).map_err(to_sql_error)?,
            confidence: row.get::<_, f32>(15)?,
            rationale: row.get(16)?,
            cost_usd: row.get::<_, Option<f64>>(17)?.unwrap_or_default(),
        }),
        None => None,
    };

    let vuln_source: Option<String> = row.get(18).ok();
    let dedup_key: Option<String> = row.get(19).ok();
    Ok(Finding {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        fingerprint: row.get(2)?,
        rule_id: row.get(3)?,
        title: row.get(4)?,
        severity: Severity::try_from(severity.as_str()).map_err(to_sql_error)?,
        file_path: row.get(6)?,
        start_line: row.get::<_, u32>(7)?,
        end_line: row.get(8)?,
        message: row.get(9)?,
        tool: row.get(10)?,
        actor_fingerprint: row.get(11)?,
        static_proof_state: static_proof_state
            .as_deref()
            .map(StaticProofState::try_from)
            .transpose()
            .map_err(to_sql_error)?,
        created_at: row.get(13)?,
        triage,
        verification: None,
        vuln_source: vuln_source.as_deref().and_then(VulnSource::parse),
        dedup_key,
    })
}

pub(crate) fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    alter_sql: &str,
) -> Result<()> {
    let mut stmt = conn.prepare(&format!("pragma table_info({table})"))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|existing| existing == column) {
        conn.execute_batch(alter_sql)?;
    }
    Ok(())
}

pub(crate) fn to_sql_error(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

pub(crate) fn fingerprint_parts(
    rule_id: &str,
    file_path: &str,
    start_line: u32,
    message: &str,
) -> String {
    let mut hasher = DefaultHasher::new();
    rule_id.hash(&mut hasher);
    file_path.hash(&mut hasher);
    start_line.hash(&mut hasher);
    message.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

pub(crate) fn merge_tool_list(existing: &str, incoming: &str) -> String {
    let mut tools: std::collections::BTreeSet<String> = existing
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    tools.insert(incoming.trim().to_string());
    tools.into_iter().collect::<Vec<_>>().join(",")
}

pub(crate) fn merge_vuln_source(
    existing: Option<VulnSource>,
    incoming: Option<VulnSource>,
) -> Option<VulnSource> {
    existing.or(incoming)
}
