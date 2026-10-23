//! Apply a bounded contiguous journal group in one projection transaction.
use super::*;

impl ProjectionDb {
    pub(super) fn apply_event_batch(
        &self,
        events: &[EventEnvelope],
    ) -> Result<Vec<ProjectionApplyReceipt>> {
        anyhow::ensure!(
            events.len() <= crate::event_log::MAX_APPEND_BATCH_EVENTS,
            "Projection batch exceeds the journal batch bound"
        );
        let tx = self
            .conn
            .unchecked_transaction()
            .context("Could not open projection batch transaction")?;
        let mut applied = meta_u64(&tx, "applied_seq")?;
        let mut receipts = Vec::with_capacity(events.len());
        for event in events {
            anyhow::ensure!(
                applied.checked_add(1) == Some(event.seq),
                "projection requires contiguous event sequence: applied {applied}, received {}",
                event.seq
            );
            insert_event_row(&tx, event)?;
            receipts.push(apply_projection_event(&tx, event)?);
            applied = event.seq;
        }
        set_meta_u64(&tx, "applied_seq", applied)?;
        tx.commit()
            .context("Could not commit projection batch transaction")?;
        Ok(receipts)
    }
}

#[cfg(test)]
mod tests;
