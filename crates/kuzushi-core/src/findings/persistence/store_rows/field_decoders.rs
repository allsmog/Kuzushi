use super::*;

pub(super) fn severity_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Severity> {
    let severity: String = row.get(5)?;
    Severity::try_from(severity.as_str()).map_err(to_sql_error)
}

pub(super) fn static_proof_state_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Option<StaticProofState>> {
    let static_proof_state: Option<String> = row.get(12)?;
    static_proof_state
        .as_deref()
        .map(StaticProofState::try_from)
        .transpose()
        .map_err(to_sql_error)
}

pub(super) fn triage_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<TriageOutcome>> {
    let Some(verdict) = row.get::<_, Option<String>>(14)? else {
        return Ok(None);
    };
    Ok(Some(TriageOutcome {
        verdict: TriageVerdict::try_from(verdict.as_str()).map_err(to_sql_error)?,
        confidence: row.get::<_, f32>(15)?,
        rationale: row.get(16)?,
        cost_usd: row.get::<_, Option<f64>>(17)?.unwrap_or_default(),
    }))
}

pub(super) fn vuln_source_from_row(row: &rusqlite::Row<'_>) -> Option<VulnSource> {
    let vuln_source: Option<String> = row.get(18).ok();
    vuln_source.as_deref().and_then(VulnSource::parse)
}
