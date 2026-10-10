//! Relationships are a derived view of existing immutable audit events.
use crate::findings::{
    Finding, FindingRelationship, FindingRelationshipEndpoint, FINDING_RELATIONSHIP_BATCH_SUBJECT,
    FINDING_RELATIONSHIP_SUBJECT,
};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

const RELATIONSHIP_RECORDS: &str = "with records as (
    select json_extract(payload_json,'$.details') as record_json,seq from audit_events where subject=?1
    union all
    select item.value as record_json,seq from audit_events,json_each(payload_json,'$.details.records') as item where subject=?2
) ";

pub(crate) fn latest_observation_endpoint(
    conn: &Connection,
    stable_key: &str,
) -> Result<Option<FindingRelationshipEndpoint>> {
    let raw: Option<String> = conn.query_row(
        "select finding_json from finding_observations where coalesce(nullif(json_extract(finding_json,'$.identityId'),''),json_extract(finding_json,'$.fingerprint'))=?1 order by created_seq desc limit 1",
        [stable_key], |row| row.get(0),
    ).optional()?;
    raw.map(|raw| {
        let finding: Finding =
            serde_json::from_str(&raw).context("relationship observation is malformed")?;
        Ok(FindingRelationshipEndpoint {
            stable_key: stable_key.into(),
            fingerprint: finding.fingerprint,
            finding_id: finding.id.context("relationship observation id missing")?,
            run_id: finding.scan_id,
        })
    })
    .transpose()
}

pub(crate) fn latest(conn: &Connection, id: &str) -> Result<Option<FindingRelationship>> {
    let body: Option<String> = conn.query_row(
        &format!("{RELATIONSHIP_RECORDS} select record_json from records where json_extract(record_json,'$.id')=?3 order by seq desc limit 1"),
        params![FINDING_RELATIONSHIP_SUBJECT,FINDING_RELATIONSHIP_BATCH_SUBJECT,id], |row| row.get(0),
    ).optional()?;
    body.map(|body| decode(&body)).transpose()
}

pub(crate) fn page(
    conn: &Connection,
    stable_key: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Vec<FindingRelationship>> {
    let mut statement = conn.prepare(&format!("{RELATIONSHIP_RECORDS}, ranked as (select record_json,seq,row_number() over (partition by json_extract(record_json,'$.id') order by seq desc) as rank from records)
         select record_json from ranked where rank=1 and (?3 is null or json_extract(record_json,'$.from.stableKey')=?3 or json_extract(record_json,'$.to.stableKey')=?3)
         order by seq desc,json_extract(record_json,'$.id') limit ?4 offset ?5"))?;
    let rows = statement.query_map(
        params![
            FINDING_RELATIONSHIP_SUBJECT,
            FINDING_RELATIONSHIP_BATCH_SUBJECT,
            stable_key,
            limit as i64,
            offset as i64
        ],
        |row| row.get::<_, String>(0),
    )?;
    rows.map(|row| decode(&row?)).collect()
}

fn decode(body: &str) -> Result<FindingRelationship> {
    let record: FindingRelationship =
        serde_json::from_str(body).context("relationship details are malformed")?;
    record.validate()?;
    Ok(record)
}
