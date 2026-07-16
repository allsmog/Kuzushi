use super::{load_phase_attempt_ledger_v2, validation};
use crate::run_lifecycle::{PhaseReceiptProjection, RunAttemptId};
use anyhow::{Context, Result};
use std::path::Path;

/// Resolve the exact typed receipt referenced by workflow-v2 for one attempt.
///
/// `None` means the compatibility ledger has no typed-v2 record. A present
/// record is always checked against its hash-linked run item before return.
pub fn load_phase_receipt_projection_v2(
    target: impl AsRef<Path>,
    attempt_id: &str,
) -> Result<Option<PhaseReceiptProjection>> {
    let Ok(attempt_id) = RunAttemptId::parse(attempt_id) else {
        return Ok(None);
    };
    let target = target.as_ref();
    let ledger = load_phase_attempt_ledger_v2(target)?;
    let Some(completed) = ledger.attempts.get(&attempt_id) else {
        return Ok(None);
    };
    validation::validate_v2_receipt_reference(target, completed)?;
    let read =
        crate::run_lifecycle::load_run_projection(target, completed.final_receipt.run_id.as_str())?;
    let receipt = read
        .projection
        .phase_receipt
        .context("referenced typed receipt is missing from its run projection")?;
    anyhow::ensure!(
        receipt.item_id == completed.final_receipt.item_id,
        "typed receipt projection resolved the wrong item"
    );
    Ok(Some(receipt))
}
