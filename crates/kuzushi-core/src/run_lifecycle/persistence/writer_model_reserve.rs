//! Reserve one bounded completion record before admitting each paid model call.
use crate::run_lifecycle::{
    RunItemEnvelopeV1, RunItemId, RunItemV1, MAX_RUN_ITEM_STREAM_BYTES,
    MAX_SERIALIZED_RUN_ITEM_BYTES,
};
use anyhow::Result;
use std::collections::BTreeSet;

const MAX_IN_FLIGHT_MODEL_CALLS: usize = 8;
const RECEIPT_BYTES: u64 = MAX_SERIALIZED_RUN_ITEM_BYTES as u64 + 1;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ModelReceiptReserve {
    active: BTreeSet<RunItemId>,
}

impl ModelReceiptReserve {
    pub(super) fn validate_batch(
        &self,
        projected_bytes: u64,
        batch: &[RunItemEnvelopeV1],
    ) -> Result<()> {
        let mut next = self.clone();
        for envelope in batch {
            next.validate_start(envelope)?;
            next.observe(envelope);
        }
        let terminal_slots = usize::from(!batch.iter().any(is_terminal_outcome));
        let reserved = (next.active.len() + terminal_slots) as u64 * RECEIPT_BYTES;
        anyhow::ensure!(
            projected_bytes.saturating_add(reserved) <= MAX_RUN_ITEM_STREAM_BYTES,
            "run-item stream budget exhausted: model receipts and terminal outcome are reserved"
        );
        Ok(())
    }

    fn validate_start(&self, envelope: &RunItemEnvelopeV1) -> Result<()> {
        if !matches!(envelope.item, RunItemV1::ModelCallStarted { .. }) {
            return Ok(());
        }
        anyhow::ensure!(
            !self.active.contains(&envelope.item_id),
            "model call already started"
        );
        anyhow::ensure!(self.active.len() < MAX_IN_FLIGHT_MODEL_CALLS,
            "run-item stream budget exhausted: eight model completion receipts are already reserved");
        Ok(())
    }

    pub(super) fn observe(&mut self, envelope: &RunItemEnvelopeV1) {
        match envelope.item {
            RunItemV1::ModelCallStarted { .. } => {
                self.active.insert(envelope.item_id);
            }
            RunItemV1::ModelCallFinished { .. } => {
                self.active.remove(&envelope.item_id);
            }
            _ => {}
        }
    }
}

fn is_terminal_outcome(envelope: &RunItemEnvelopeV1) -> bool {
    matches!(envelope.item, RunItemV1::TerminalOutcome { .. })
}

#[cfg(test)]
#[path = "writer_model_reserve_tests.rs"]
mod tests;
