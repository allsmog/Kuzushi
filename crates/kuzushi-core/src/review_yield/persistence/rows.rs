use rusqlite::Row;

use crate::findings::{ReviewDecisionProvenance, ReviewDecisionVerdict};

/// One projected review decision, read with the author kept as the raw stored
/// string.
///
/// `review_decisions.author` is not enum-constrained — the projection falls
/// back to the event actor — so parsing it into `TriageAuthor` here would drop
/// or coerce rows the census must still count. The verdict, in contrast, is
/// always written through `ReviewDecisionVerdict::as_str`, so an unrecognized
/// verdict is corruption and fails loudly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRow {
    pub identity_id: Option<String>,
    pub verdict: ReviewDecisionVerdict,
    pub author: String,
    pub dismiss_reason: Option<String>,
    pub provenance: Option<ReviewDecisionProvenance>,
}

/// Snapshot metadata of one pre-cutoff finding observation. Deliberately
/// carries no path, title, message, or snippet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationMeta {
    pub observation_hash: String,
    pub snapshot_hash: String,
    pub created_seq: u64,
    pub run_id: String,
    pub tool: String,
}

pub(super) fn decision_row(row: &Row<'_>) -> rusqlite::Result<DecisionRow> {
    let raw_verdict: String = row.get(1)?;
    let verdict = ReviewDecisionVerdict::from_str(&raw_verdict)
        .ok_or_else(|| row_error(format!("unknown review decision verdict {raw_verdict:?}")))?;
    Ok(DecisionRow {
        identity_id: row.get(0)?,
        verdict,
        author: row.get(2)?,
        dismiss_reason: row.get(3)?,
        provenance: decision_provenance(row)?,
    })
}

fn decision_provenance(row: &Row<'_>) -> rusqlite::Result<Option<ReviewDecisionProvenance>> {
    let event_seq: Option<i64> = row.get(4)?;
    let event_hash: Option<String> = row.get(5)?;
    let (Some(event_seq), Some(event_hash)) = (event_seq, event_hash) else {
        return Ok(None);
    };
    let read_watermark: Option<i64> = row.get(6)?;
    Ok(Some(ReviewDecisionProvenance {
        event_seq: non_negative(event_seq, "decision event seq")?,
        event_hash,
        read_watermark: read_watermark
            .map(|value| non_negative(value, "decision read cutoff"))
            .transpose()?,
    }))
}

pub(super) fn observation_row(row: &Row<'_>) -> rusqlite::Result<(String, ObservationMeta)> {
    let identity_id: String = row.get(0)?;
    let created_seq: i64 = row.get(3)?;
    let meta = ObservationMeta {
        observation_hash: row.get(1)?,
        snapshot_hash: row.get(2)?,
        created_seq: non_negative(created_seq, "observation seq")?,
        run_id: row.get(4)?,
        tool: row.get(5)?,
    };
    Ok((identity_id, meta))
}

fn non_negative(value: i64, label: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| row_error(format!("negative {label}: {value}")))
}

fn row_error(message: String) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(message)))
}
