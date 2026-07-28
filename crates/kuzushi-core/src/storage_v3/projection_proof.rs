use crate::event_log::{EventEnvelope, EventKind};
use anyhow::{Context, Result};
use rusqlite::{params, Transaction};

use super::projection_fts::rebuild_fts_if_available;
use super::projection_payload::{
    payload_i64, payload_str, payload_u64, require_payload_i64, require_payload_str,
};
use super::sql_seq;

const PATCH_ATTEMPT_SQL: &str = r#"
insert into patch_attempt_events(
  event_hash, seq, stable_fp, fingerprint, patch_run_id, repo,
  diff_object, diff_size_bytes, status, iterations, build_command,
  test_command, worktree_path, cost_usd, provider_spend_unresolved,
  validator_log, history_json, actor, created_at, payload_json
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
on conflict(event_hash) do nothing
"#;

const VERIFICATION_SQL: &str = r#"
insert into verification_events(
  event_hash, seq, stable_fp, finding_id, identity_id,
  verification_run_id, verified_scan_id, provenance_json, proof_level,
  proof_verdict, backend, language, harness_path, crash_evidence,
  duration_ms, cost_usd, notes_json, actor, created_at, payload_json
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
on conflict(event_hash) do nothing
"#;

pub(super) fn project_verification_event(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<()> {
    if event.event_kind != EventKind::VerificationRecorded {
        return Ok(());
    }
    tx.execute(
        VERIFICATION_SQL,
        params![
            event.event_hash.as_str(),
            sql_seq(event.seq)?,
            require_payload_str(&event.payload, "stableFp")?,
            payload_i64(&event.payload, "findingId"),
            payload_str(&event.payload, "identityId"),
            payload_str(&event.payload, "verificationRunId"),
            payload_str(&event.payload, "verifiedScanId"),
            verification_provenance_json(&event.payload)?,
            require_payload_i64(&event.payload, "proofLevel")?,
            require_payload_str(&event.payload, "proofVerdict")?,
            require_payload_str(&event.payload, "backend")?,
            payload_str(&event.payload, "language"),
            payload_str(&event.payload, "harnessPath"),
            payload_str(&event.payload, "crashEvidence"),
            require_payload_i64(&event.payload, "durationMs")?,
            micros_cost_usd(&event.payload, "costUsdMicros").unwrap_or(0.0),
            json_field(&event.payload, "notes", "[]"),
            event.actor,
            event.created_at,
            event.payload.to_string(),
        ],
    )?;
    project_verification_search(tx, event)?;
    Ok(())
}

fn verification_provenance_json(payload: &serde_json::Value) -> Result<Option<String>> {
    let Some(value) = payload.get("provenance").filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let provenance: crate::findings::VerificationProvenance = serde_json::from_value(value.clone())
        .context("verification event provenance is invalid")?;
    provenance.validate()?;
    Ok(Some(serde_json::to_string(&provenance)?))
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
            sql_seq(event.seq)?,
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
            patch_cost_usd(&event.payload)?,
            patch_provider_spend_unresolved(&event.payload)?,
            payload_str(&event.payload, "validatorLog"),
            payload_str(&event.payload, "historyJson").unwrap_or("[]"),
            event.actor,
            event.created_at,
            event.payload.to_string(),
        ],
    )?;
    Ok(())
}

fn patch_provider_spend_unresolved(payload: &serde_json::Value) -> Result<bool> {
    match payload.get("providerSpendUnresolved") {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(serde_json::Value::Bool(value)) => Ok(*value),
        Some(_) => anyhow::bail!("event payload providerSpendUnresolved must be a boolean"),
    }
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
        payload_str(payload, "proofVerdict")
            .unwrap_or("")
            .to_string(),
        payload_str(payload, "backend").unwrap_or("").to_string(),
        payload_str(payload, "language").unwrap_or("").to_string(),
        payload_str(payload, "harnessPath")
            .unwrap_or("")
            .to_string(),
        payload_str(payload, "crashEvidence")
            .unwrap_or("")
            .to_string(),
        json_field(payload, "notes", ""),
    ]
    .join(" ")
}

fn patch_cost_usd(payload: &serde_json::Value) -> Result<Option<f64>> {
    match payload.get("costUsd") {
        Some(value) if !value.is_null() => {
            let value = value
                .as_f64()
                .ok_or_else(|| anyhow::anyhow!("event payload costUsd must be a number"))?;
            let cost = crate::runtime::RuntimeCost::from_usd(value, "patch event costUsd")?;
            Ok(Some(cost.usd()))
        }
        _ => micros_cost_usd(payload, "costUsdMicros")
            .map(|value| {
                crate::runtime::RuntimeCost::from_usd(value, "patch event costUsdMicros")
                    .map(crate::runtime::RuntimeCost::usd)
            })
            .transpose(),
    }
}

fn micros_cost_usd(payload: &serde_json::Value, key: &str) -> Option<f64> {
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
