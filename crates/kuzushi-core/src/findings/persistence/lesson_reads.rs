//! Lesson revisions are immutable audit records, projected through the existing ledger.
use crate::findings::{FindingLesson, LessonRef, FINDING_LESSON_SUBJECT};
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

pub(crate) fn latest(conn: &Connection, id: &str) -> Result<Option<FindingLesson>> {
    let raw: Option<String> = conn.query_row(
        "select json_extract(payload_json,'$.details') from audit_events where subject=?1 and json_extract(payload_json,'$.details.id')=?2 order by seq desc limit 1",
        params![FINDING_LESSON_SUBJECT,id], |row| row.get(0),
    ).optional()?;
    raw.map(|raw| decode(&raw)).transpose()
}

pub(crate) fn exact(conn: &Connection, reference: &LessonRef) -> Result<FindingLesson> {
    let revision = i64::try_from(reference.revision).context("Invalid lesson revision")?;
    let raw: String = conn.query_row(
        "select json_extract(payload_json,'$.details') from audit_events where subject=?1 and json_extract(payload_json,'$.details.id')=?2 and json_extract(payload_json,'$.details.revision')=?3 order by seq desc limit 1",
        params![FINDING_LESSON_SUBJECT,reference.lesson_id,revision], |row| row.get(0),
    ).optional()?.context("Lesson revision is missing")?;
    let record = decode(&raw)?;
    anyhow::ensure!(
        &record.reference()? == reference,
        "Lesson revision digest does not match"
    );
    Ok(record)
}

pub(crate) fn page(conn: &Connection, limit: usize, offset: usize) -> Result<Vec<FindingLesson>> {
    let mut statement = conn.prepare(
        "with records as (select json_extract(payload_json,'$.details') as record,seq,row_number() over (partition by json_extract(payload_json,'$.details.id') order by seq desc) as rank from audit_events where subject=?1)
         select record from records where rank=1 order by seq desc limit ?2 offset ?3")?;
    let rows = statement.query_map(
        params![FINDING_LESSON_SUBJECT, limit as i64, offset as i64],
        |row| row.get::<_, String>(0),
    )?;
    rows.map(|raw| decode(&raw?)).collect()
}

fn decode(raw: &str) -> Result<FindingLesson> {
    let record: FindingLesson = serde_json::from_str(raw).context("Lesson record is malformed")?;
    record.validate()?;
    Ok(record)
}
