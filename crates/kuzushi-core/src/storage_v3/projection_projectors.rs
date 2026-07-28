use self::inventory::{
    project_attack_surface_indexed, project_file_deleted, project_file_indexed,
    project_snapshot_indexed,
};
use super::projection_audit::project_audit_event;
use super::projection_finding_lifecycle::project_finding_lifecycle_status;
use super::projection_observations::project_finding_observation;
use super::projection_patch_lifecycle::project_patch_lifecycle_event;
use super::projection_payload::{payload_str, require_payload_f64, require_payload_str};
use super::projection_proof::{project_patch_attempt_event, project_verification_event};
use super::projection_review::project_review_decision;
use super::projection_runs::project_run_lifecycle_event;
use super::sql_seq;
use super::ProjectionApplyReceipt;
use crate::event_log::{EventEnvelope, EventKind};
use anyhow::Result;
use rusqlite::{params, Transaction};

mod inventory;

pub(super) fn apply_projection_event(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<ProjectionApplyReceipt> {
    project_snapshot_indexed(tx, event)?;
    project_run_lifecycle_event(tx, event)?;
    project_file_indexed(tx, event)?;
    project_file_deleted(tx, event)?;
    project_attack_surface_indexed(tx, event)?;
    let finding_id = project_finding_observation(tx, event)?;
    project_finding_rekeyed(tx, event)?;
    project_finding_lifecycle_status(tx, event)?;
    project_verification_event(tx, event)?;
    project_patch_attempt_event(tx, event)?;
    project_patch_lifecycle_event(tx, event)?;
    project_audit_event(tx, event)?;
    let review_decision_id = project_review_decision(tx, event)?;
    Ok(ProjectionApplyReceipt {
        review_decision_id,
        finding_id,
    })
}

fn project_finding_rekeyed(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    if event.event_kind != EventKind::FindingRekeyed {
        return Ok(());
    }
    let old_fp = require_payload_str(&event.payload, "oldFp")?;
    let new_fp = require_payload_str(&event.payload, "newFp")?;
    tx.execute(
        r#"
        insert into rekey_edges(old_fp, new_fp, event_hash, method, confidence)
        values (?1, ?2, ?3, ?4, ?5)
        on conflict(old_fp, new_fp, event_hash) do update set
          method = excluded.method,
          confidence = excluded.confidence
        "#,
        params![
            old_fp,
            new_fp,
            event.event_hash.as_str(),
            payload_str(&event.payload, "method").unwrap_or("unknown"),
            require_payload_f64(&event.payload, "confidence")?,
        ],
    )?;
    tx.execute(
        "update stable_findings
            set current_status = 'rekeyed', updated_seq = ?2
          where stable_fp = ?1",
        params![old_fp, sql_seq(event.seq)?],
    )?;
    attach_model_dedupe_identity(tx, event)?;
    Ok(())
}

/// Model-dedupe rekeys carry the canonical identity plus the duplicate's raw
/// fingerprint in their evidence payload; attaching that fingerprint to the
/// canonical identity makes independent rediscovery converge on one identity.
/// Legacy rekey events without the evidence keys replay unchanged.
fn attach_model_dedupe_identity(tx: &Transaction<'_>, event: &EventEnvelope) -> Result<()> {
    let Some(evidence) = event.payload.get("evidence") else {
        return Ok(());
    };
    let identity_id = evidence.get("canonicalIdentityId").and_then(|v| v.as_str());
    let fingerprint = evidence
        .get("duplicateFingerprint")
        .and_then(|v| v.as_str());
    let (Some(identity_id), Some(fingerprint)) = (identity_id, fingerprint) else {
        return Ok(());
    };
    tx.execute(
        r#"
        insert or ignore into finding_identity_fingerprints
            (identity_id, fingerprint, match_basis, created_at)
        select ?1, ?2, 'model_dedupe', ?3
         where exists (select 1 from finding_identities where identity_id = ?1)
        "#,
        params![identity_id, fingerprint, event.created_at],
    )?;
    Ok(())
}
