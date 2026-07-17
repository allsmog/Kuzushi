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
    Ok(())
}
