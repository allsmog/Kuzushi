use crate::event_log::{EventEnvelope, EventKind};
use anyhow::{Context, Result};
use rusqlite::{params, Transaction};

use super::projection_fts::rebuild_fts_if_available;
use super::projection_payload::{
    payload_f64, payload_i64, payload_str, payload_u64, require_payload_str, require_payload_u64,
    stable_fp_from_payload, triage_verdict_for_review,
};
use super::{sql_seq, sql_watermark};

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
    let review_decision_id =
        insert_review_decision_row(tx, event, finding_id, verdict, triage_verdict, confidence)?;
    project_finding_triage_json(tx, event, finding_id, triage_verdict, confidence)?;
    project_review_search(tx, event, verdict)?;
    Ok(Some(review_decision_id))
}

fn insert_review_decision_row(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
    finding_id: i64,
    verdict: &str,
    triage_verdict: Option<&str>,
    confidence: f64,
) -> Result<i64> {
    let context = decision_insert_context(event)?;
    tx.execute(
        r#"
        insert into review_decisions(
          finding_id, identity_id, decision_verdict, triage_verdict, confidence,
          rationale, author, created_at, dismiss_reason, dismissed_by,
          decision_event_seq, decision_event_hash, decision_read_watermark,
          review_session_id, propagation_basis, source_finding_ids_json
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
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
            payload_str(&event.payload, "dismissReason"),
            payload_str(&event.payload, "dismissedBy"),
            sql_seq(event.seq)?,
            event.event_hash.as_str(),
            context.read_watermark,
            payload_str(&event.payload, "reviewSessionId"),
            context.propagation_basis,
            context.source_finding_ids_json,
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

struct DecisionInsertContext<'a> {
    read_watermark: Option<i64>,
    propagation_basis: Option<&'a str>,
    source_finding_ids_json: Option<String>,
}

fn decision_insert_context(event: &EventEnvelope) -> Result<DecisionInsertContext<'_>> {
    let read_watermark = payload_u64(&event.payload, "readWatermark")
        .map(sql_watermark)
        .transpose()?;
    let (propagation_basis, source_finding_ids_json) = propagation_payload(event)?;
    Ok(DecisionInsertContext {
        read_watermark,
        propagation_basis,
        source_finding_ids_json,
    })
}

fn propagation_payload(event: &EventEnvelope) -> Result<(Option<&str>, Option<String>)> {
    let basis = payload_str(&event.payload, "propagationBasis");
    let source_ids = propagation_source_ids_json(event)?;
    anyhow::ensure!(
        basis.is_some() == source_ids.is_some(),
        "review propagation basis and source finding ids must appear together"
    );
    if let Some(basis) = basis {
        crate::findings::FindingIdentityBasis::from_str(basis)
            .context("review propagation basis is unknown")?;
    }
    Ok((basis, source_ids))
}

fn propagation_source_ids_json(event: &EventEnvelope) -> Result<Option<String>> {
    let Some(value) = event.payload.get("sourceFindingIds") else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let ids = value
        .as_array()
        .filter(|ids| !ids.is_empty() && ids.iter().all(|id| id.as_i64().is_some_and(|id| id > 0)))
        .context("review propagation sourceFindingIds must be non-empty positive integers")?;
    serde_json::to_string(ids)
        .map(Some)
        .context("Could not serialize review propagation source finding ids")
}

fn sql_rank(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| anyhow::anyhow!("review session rank exceeds SQLite INTEGER range: {value}"))
}

/// Projects one prospective review session. Replay-idempotent through the
/// event hash, so rebuilding the projection reproduces exactly one row per
/// recorded session.
pub(super) fn project_review_session(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    if event.event_kind != EventKind::ReviewSessionStarted {
        return Ok(());
    }
    tx.execute(
        r#"
        insert into review_sessions(
          event_hash, seq, review_session_id, stable_fp, identity_id, finding_id,
          feature_schema_id, feature_snapshot_hash, feature_cutoff_seq, model_id,
          eligibility, baseline_rank, shadow_rank, shadow_rank_objective,
          queue_size, proof_band, severity, created_at
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
        on conflict(event_hash) do nothing
        "#,
        params![
            event.event_hash.as_str(),
            sql_seq(event.seq)?,
            require_payload_str(&event.payload, "reviewSessionId")?,
            require_payload_str(&event.payload, "stableFp")?,
            payload_str(&event.payload, "identityId"),
            payload_i64(&event.payload, "findingId"),
            require_payload_str(&event.payload, "featureSchemaId")?,
            payload_str(&event.payload, "featureSnapshotHash"),
            sql_seq(require_payload_u64(&event.payload, "featureCutoffSeq")?)?,
            require_payload_str(&event.payload, "modelId")?,
            require_payload_str(&event.payload, "eligibility")?,
            sql_rank(require_payload_u64(&event.payload, "baselineRank")?)?,
            payload_u64(&event.payload, "shadowRank")
                .map(sql_rank)
                .transpose()?,
            payload_str(&event.payload, "shadowRankObjective"),
            sql_rank(require_payload_u64(&event.payload, "queueSize")?)?,
            require_payload_str(&event.payload, "proofBand")?,
            require_payload_str(&event.payload, "severity")?,
            event.created_at,
        ],
    )?;
    Ok(())
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
    let (cost_usd, cost_usd_exact) = projected_triage_cost(event)?;
    write_finding_triage_projection(
        tx,
        event,
        finding_id,
        triage_verdict,
        confidence,
        cost_usd,
        cost_usd_exact,
    )
}

fn projected_triage_cost(event: &EventEnvelope) -> Result<(f64, bool)> {
    let cost_usd = payload_f64(&event.payload, "triageCostUsd").unwrap_or(0.0);
    crate::runtime::RuntimeCost::from_usd(cost_usd, "projected triage cost")?;
    let exact = event
        .payload
        .get("triageCostUsdExact")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    Ok((cost_usd, exact))
}

#[allow(clippy::too_many_arguments)]
fn write_finding_triage_projection(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
    finding_id: i64,
    triage_verdict: &str,
    confidence: f64,
    cost_usd: f64,
    cost_usd_exact: bool,
) -> Result<()> {
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
                   'cost_usd', ?5,
                   'cost_usd_exact', case when ?6 then json('true') else json('false') end
                 ),
                 '$.triaged_by',
                 ?7
               )
         where finding_json is not null
           and json_extract(finding_json, '$.id') = ?1
        "#,
        params![
            finding_id,
            triage_verdict,
            confidence,
            payload_str(&event.payload, "rationale").unwrap_or(""),
            cost_usd,
            cost_usd_exact,
            payload_str(&event.payload, "author").unwrap_or(event.actor.as_str()),
        ],
    )?;
    Ok(())
}

fn project_review_search(tx: &Transaction<'_>, event: &EventEnvelope, verdict: &str) -> Result<()> {
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
