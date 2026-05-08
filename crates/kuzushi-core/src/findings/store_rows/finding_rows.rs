use super::field_decoders::{
    severity_from_row, static_proof_state_from_row, triage_from_row, vuln_source_from_row,
};
use super::*;

pub(crate) fn row_to_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    let row = finding_row(row)?;
    Ok(Finding {
        id: row.id,
        scan_id: row.scan_id,
        fingerprint: row.fingerprint,
        rule_id: row.rule_id,
        title: row.title,
        severity: row.severity,
        file_path: row.file_path,
        start_line: row.start_line,
        end_line: row.end_line,
        message: row.message,
        tool: row.tool,
        actor_fingerprint: row.actor_fingerprint,
        static_proof_state: row.static_proof_state,
        created_at: row.created_at,
        triage: row.triage,
        verification: None,
        vuln_source: row.vuln_source,
        dedup_key: row.dedup_key,
    })
}

struct FindingRow {
    id: Option<i64>,
    scan_id: Option<String>,
    fingerprint: String,
    rule_id: String,
    title: String,
    severity: Severity,
    file_path: String,
    start_line: u32,
    end_line: Option<u32>,
    message: String,
    tool: String,
    actor_fingerprint: Option<String>,
    static_proof_state: Option<StaticProofState>,
    created_at: String,
    triage: Option<TriageOutcome>,
    vuln_source: Option<VulnSource>,
    dedup_key: Option<String>,
}

fn finding_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FindingRow> {
    let identity = finding_identity_row(row)?;
    let location = finding_location_row(row)?;
    let analysis = finding_analysis_row(row)?;
    Ok(FindingRow {
        id: identity.id,
        scan_id: identity.scan_id,
        fingerprint: identity.fingerprint,
        rule_id: identity.rule_id,
        title: identity.title,
        severity: analysis.severity,
        file_path: location.file_path,
        start_line: location.start_line,
        end_line: location.end_line,
        message: analysis.message,
        tool: analysis.tool,
        actor_fingerprint: analysis.actor_fingerprint,
        static_proof_state: analysis.static_proof_state,
        created_at: analysis.created_at,
        triage: analysis.triage,
        vuln_source: analysis.vuln_source,
        dedup_key: analysis.dedup_key,
    })
}

struct FindingIdentityRow {
    id: Option<i64>,
    scan_id: Option<String>,
    fingerprint: String,
    rule_id: String,
    title: String,
}

fn finding_identity_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FindingIdentityRow> {
    Ok(FindingIdentityRow {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        fingerprint: row.get(2)?,
        rule_id: row.get(3)?,
        title: row.get(4)?,
    })
}

struct FindingLocationRow {
    file_path: String,
    start_line: u32,
    end_line: Option<u32>,
}

fn finding_location_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FindingLocationRow> {
    Ok(FindingLocationRow {
        file_path: row.get(6)?,
        start_line: row.get::<_, u32>(7)?,
        end_line: row.get(8)?,
    })
}

struct FindingAnalysisRow {
    severity: Severity,
    message: String,
    tool: String,
    actor_fingerprint: Option<String>,
    static_proof_state: Option<StaticProofState>,
    created_at: String,
    triage: Option<TriageOutcome>,
    vuln_source: Option<VulnSource>,
    dedup_key: Option<String>,
}

fn finding_analysis_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FindingAnalysisRow> {
    Ok(FindingAnalysisRow {
        severity: severity_from_row(row)?,
        message: row.get(9)?,
        tool: row.get(10)?,
        actor_fingerprint: row.get(11)?,
        static_proof_state: static_proof_state_from_row(row)?,
        created_at: row.get(13)?,
        triage: triage_from_row(row)?,
        vuln_source: vuln_source_from_row(row),
        dedup_key: row.get(19).ok(),
    })
}
