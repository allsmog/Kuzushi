use crate::event_log::{EventEnvelope, EventKind};
use anyhow::Result;
use rusqlite::{params, Transaction};

use super::projection_fts::rebuild_fts_if_available;
use super::projection_payload::{
    payload_i64, payload_str, require_payload_str, require_payload_u64, stable_fp_from_payload,
    triage_verdict_for_review,
};

pub(super) fn project_review_decision(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<Option<i64>> {
    if !matches!(
        event.event_kind,
        EventKind::TriageDecided | EventKind::SuppressionAdded
    ) {
        return Ok(None);
    }
    let Some(finding_id) = payload_i64(&event.payload, "findingId") else {
        return Ok(None);
    };
    let verdict = require_payload_str(&event.payload, "verdict")?;
    let confidence = require_payload_u64(&event.payload, "confidenceMillis")? as f64 / 1000.0;
    let triage_verdict = triage_verdict_for_review(verdict)?;
    tx.execute(
        r#"
        insert into review_decisions(
          finding_id, identity_id, decision_verdict, triage_verdict, confidence,
          rationale, author, created_at
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            finding_id,
            payload_str(&event.payload, "identityId"),
            verdict,
            triage_verdict,
            confidence,
            payload_str(&event.payload, "rationale").unwrap_or(""),
            payload_str(&event.payload, "author").unwrap_or(event.actor.as_str()),
            event.created_at,
        ],
    )?;
    let review_decision_id = tx.last_insert_rowid();
    project_finding_triage_json(tx, event, finding_id, triage_verdict, confidence)?;
    project_review_search(tx, event, verdict)?;
    Ok(Some(review_decision_id))
}

fn project_finding_triage_json(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
    finding_id: i64,
    triage_verdict: Option<&str>,
    confidence: f64,
) -> Result<()> {
    if event
        .payload
        .get("updatesFindingTriage")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return Ok(());
    }
    let Some(triage_verdict) = triage_verdict else {
        return Ok(());
    };
    tx.execute(
        r#"
        update finding_observations
           set finding_json = json_set(
                 finding_json,
                 '$.triage',
                 json_object(
                   'verdict', ?2,
                   'confidence', ?3,
                   'rationale', ?4,
                   'cost_usd', 0.0
                 ),
                 '$.triaged_by',
                 ?5
               )
         where finding_json is not null
           and json_extract(finding_json, '$.id') = ?1
        "#,
        params![
            finding_id,
            triage_verdict,
            confidence,
            payload_str(&event.payload, "rationale").unwrap_or(""),
            payload_str(&event.payload, "author").unwrap_or(event.actor.as_str()),
        ],
    )?;
    Ok(())
}

fn project_review_search(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
    verdict: &str,
) -> Result<()> {
    let Some(stable_fp) = stable_fp_from_payload(&event.payload) else {
        return Ok(());
    };
    let triage_text = [
        verdict.to_string(),
        payload_str(&event.payload, "rationale")
            .unwrap_or("")
            .to_string(),
        payload_str(&event.payload, "author")
            .unwrap_or(event.actor.as_str())
            .to_string(),
    ]
    .join(" ");
    tx.execute(
        r#"
        insert into finding_search_content(stable_fp, triage_text)
        values (?1, ?2)
        on conflict(stable_fp) do update set triage_text = excluded.triage_text
        "#,
        params![stable_fp, triage_text],
    )?;
    rebuild_fts_if_available(tx)
}
