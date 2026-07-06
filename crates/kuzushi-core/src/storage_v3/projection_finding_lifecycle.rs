use crate::event_log::{EventEnvelope, EventKind};
use anyhow::Result;
use rusqlite::{params, Transaction};

use super::projection_payload::require_payload_str;

pub(super) fn project_finding_lifecycle_status(
    tx: &Transaction<'_>,
    event: &EventEnvelope,
) -> Result<()> {
    let Some(status) = lifecycle_status(event.event_kind) else {
        return Ok(());
    };
    tx.execute(
        "update stable_findings
            set current_status = ?2, updated_seq = ?3
          where stable_fp = ?1",
        params![
            require_payload_str(&event.payload, "stableFp")?,
            status,
            event.seq
        ],
    )?;
    Ok(())
}

fn lifecycle_status(event_kind: EventKind) -> Option<&'static str> {
    match event_kind {
        EventKind::FindingDisappeared => Some("stale"),
        EventKind::FindingReopened
        | EventKind::SuppressionExpired
        | EventKind::SuppressionRemoved => Some("open"),
        EventKind::SuppressionAdded => Some("suppressed"),
        _ => None,
    }
}
