use crate::event_log::{EventEnvelope, EventKind};
use anyhow::Result;
use rusqlite::{params, Transaction};

use super::projection_fts::rebuild_fts_if_available;
use super::projection_payload::{
    payload_i64, payload_str, payload_u64, require_payload_i64, require_payload_str,
};

const PATCH_ATTEMPT_SQL: &str = r#"
insert into patch_attempt_events(
  event_hash, seq, stable_fp, fingerprint, patch_run_id, repo,
  diff_object, diff_size_bytes, status, iterations, build_command,
  test_command, worktree_path, cost_usd, validator_log,
  history_json, actor, created_at, payload_json
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
on conflict(event_hash) do nothing
"#;

pub(super) fn project_verification_event(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    if event.event_kind != EventKind::VerificationRecorded {
        return Ok(());
    }
    tx.execute(
        r#"
        insert into verification_events(
          event_hash, seq, stable_fp, finding_id, identity_id, proof_level,
          proof_verdict, backend, language, harness_path, crash_evidence,
          duration_ms, cost_usd, notes_json, actor, created_at, payload_json
        )
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
        on conflict(event_hash) do nothing
        "#,
        params![
            event.event_hash.as_str(),
            event.seq,
            require_payload_str(&event.payload, "stableFp")?,
            payload_i64(&event.payload, "findingId"),
            payload_str(&event.payload, "identityId"),
            require_payload_i64(&event.payload, "proofLevel")?,
            require_payload_str(&event.payload, "proofVerdict")?,
            require_payload_str(&event.payload, "backend")?,
            payload_str(&event.payload, "language"),
            payload_str(&event.payload, "harnessPath"),
            payload_str(&event.payload, "crashEvidence"),
            require_payload_i64(&event.payload, "durationMs")?,
            cost_usd(&event.payload, "costUsdMicros").unwrap_or(0.0),
            json_field(&event.payload, "notes", "[]"),
            event.actor,
            event.created_at,
            event.payload.to_string(),
        ],
    )?;
    project_verification_search(tx, event)?;
    Ok(())
}

pub(super) fn project_patch_attempt_event(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<()> {
    if event.event_kind != EventKind::PatchAttemptRecorded {
        return Ok(());
    }
    tx.execute(
        PATCH_ATTEMPT_SQL,
        params![
            event.event_hash.as_str(),
            event.seq,
            require_payload_str(&event.payload, "stableFp")?,
            require_payload_str(&event.payload, "fingerprint")?,
            require_payload_str(&event.payload, "patchRunId")?,
            require_payload_str(&event.payload, "repo")?,
            payload_str(&event.payload, "diffObject"),
            payload_i64(&event.payload, "diffSizeBytes"),
            require_payload_str(&event.payload, "status")?,
            require_payload_i64(&event.payload, "iterations")?,
            payload_str(&event.payload, "buildCommand"),
            payload_str(&event.payload, "testCommand"),
            payload_str(&event.payload, "worktreePath"),
            cost_usd(&event.payload, "costUsdMicros"),
            payload_str(&event.payload, "validatorLog"),
            payload_str(&event.payload, "historyJson").unwrap_or("[]"),
            event.actor,
            event.created_at,
            event.payload.to_string(),
        ],
    )?;
    Ok(())
}

fn project_verification_search(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    let stable_fp = require_payload_str(&event.payload, "stableFp")?;
    let verification_text = verification_search_text(&event.payload);
    tx.execute(
        r#"
        insert into finding_search_content(stable_fp, verification_text)
        values (?1, ?2)
        on conflict(stable_fp) do update set
          verification_text = excluded.verification_text
        "#,
        params![stable_fp, verification_text],
    )?;
    rebuild_fts_if_available(tx)
}

fn verification_search_text(payload: &serde_json::Value) -> String {
    [
        payload_str(payload, "proofVerdict").unwrap_or("").to_string(),
        payload_str(payload, "backend").unwrap_or("").to_string(),
        payload_str(payload, "language").unwrap_or("").to_string(),
        payload_str(payload, "harnessPath").unwrap_or("").to_string(),
        payload_str(payload, "crashEvidence").unwrap_or("").to_string(),
        json_field(payload, "notes", ""),
    ]
    .join(" ")
}

fn cost_usd(payload: &serde_json::Value, key: &str) -> Option<f64> {
    payload_i64(payload, key)
        .or_else(|| payload_u64(payload, key).and_then(|value| i64::try_from(value).ok()))
        .map(|micros| micros as f64 / 1_000_000.0)
}

fn json_field(payload: &serde_json::Value, key: &str, fallback: &str) -> String {
    payload
        .get(key)
        .map(serde_json::Value::to_string)
        .unwrap_or_else(|| fallback.to_string())
}
