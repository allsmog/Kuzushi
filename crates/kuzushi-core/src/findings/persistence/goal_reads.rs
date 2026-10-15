//! Immutable goal assessment revisions are projected through existing audit events.
use super::*;
use crate::findings::{FindingGoalAssessment, FindingGoalBasis, GOAL_RELEVANCE_SUBJECT};

pub(crate) fn latest(conn: &Connection, id: &str) -> Result<Option<FindingGoalAssessment>> {
    let raw: Option<String> = conn.query_row(
        "select json_extract(payload_json,'$.details') from audit_events where subject=?1 and json_extract(payload_json,'$.details.id')=?2 order by seq desc limit 1",
        params![GOAL_RELEVANCE_SUBJECT,id], |row| row.get(0),
    ).optional()?;
    raw.map(decode).transpose()
}

pub(crate) fn history(conn: &Connection, finding_id: i64) -> Result<Vec<FindingGoalAssessment>> {
    let mut statement = conn.prepare(
        "select json_extract(payload_json,'$.details') from audit_events where subject=?1 and json_extract(payload_json,'$.details.basis.findingId')=?2 order by seq asc")?;
    let rows = statement.query_map(params![GOAL_RELEVANCE_SUBJECT, finding_id], |row| {
        row.get::<_, String>(0)
    })?;
    rows.map(|row| decode(row?)).collect()
}

pub(crate) fn for_brief(
    conn: &Connection,
    brief: &crate::capabilities::campaign::BriefReference,
) -> Result<Vec<FindingGoalAssessment>> {
    let mut statement = conn.prepare(
        "with records as (select json_extract(payload_json,'$.details') as record,row_number() over (partition by json_extract(payload_json,'$.details.id') order by seq desc) as rank from audit_events where subject=?1 and json_extract(payload_json,'$.details.briefRef.briefId')=?2 and json_extract(payload_json,'$.details.briefRef.revision')=?3) select record from records where rank=1")?;
    let rows = statement.query_map(
        params![GOAL_RELEVANCE_SUBJECT, brief.brief_id, brief.revision],
        |row| row.get::<_, String>(0),
    )?;
    rows.map(|row| {
        let record = decode(row?)?;
        anyhow::ensure!(
            &record.brief_ref == brief,
            "Goal assessment brief receipt differs"
        );
        Ok(record)
    })
    .collect()
}

pub(crate) fn basis(conn: &Connection, finding_id: i64) -> Result<FindingGoalBasis> {
    conn.query_row(
        "select stable_fp,json_extract(finding_json,'$.fingerprint'),created_seq,run_id,snapshot_hash from finding_observations where json_extract(finding_json,'$.id')=?1 order by created_seq desc limit 1",
        params![finding_id], |row| Ok(FindingGoalBasis {
            finding_id, stable_key: row.get(0)?, fingerprint: row.get(1)?,
            observation_seq: row.get::<_, i64>(2)? as u64, run_id: row.get(3)?, snapshot_hash: row.get(4)?,
        }),
    ).optional()?.context("Goal relevance needs a recorded finding generation")
}

fn decode(raw: String) -> Result<FindingGoalAssessment> {
    let record: FindingGoalAssessment =
        serde_json::from_str(&raw).context("Goal assessment is malformed")?;
    record.validate()?;
    Ok(record)
}

pub(crate) fn bases(
    conn: &Connection,
    findings: &[Finding],
) -> Result<std::collections::BTreeMap<i64, FindingGoalBasis>> {
    let ids = serde_json::to_string(
        &findings
            .iter()
            .filter_map(|finding| finding.id)
            .collect::<Vec<_>>(),
    )?;
    let mut statement = conn.prepare("with candidates as (select json_extract(finding_json,'$.id') as id, stable_fp, json_extract(finding_json,'$.fingerprint') as fingerprint, created_seq, run_id, snapshot_hash, row_number() over (partition by json_extract(finding_json,'$.id') order by created_seq desc) as rank from finding_observations where json_extract(finding_json,'$.id') in (select value from json_each(?1))) select id, stable_fp, fingerprint, created_seq, run_id, snapshot_hash from candidates where rank=1")?;
    let rows = statement.query_map(params![ids], |row| {
        let id = row.get(0)?;
        Ok((
            id,
            FindingGoalBasis {
                finding_id: id,
                stable_key: row.get(1)?,
                fingerprint: row.get(2)?,
                observation_seq: row.get::<_, i64>(3)? as u64,
                run_id: row.get(4)?,
                snapshot_hash: row.get(5)?,
            },
        ))
    })?;
    rows.collect::<rusqlite::Result<_>>()
        .context("Could not batch goal observation bases")
}
