use super::{DecisionWrite, StorageWriter};
use anyhow::{bail, Result};

impl StorageWriter {
    pub(in crate::storage_v3::writer_actor) fn forward_or_reject_stale_decision(
        &self,
        decision: &mut DecisionWrite,
    ) -> Result<()> {
        if let Some(forwarded) = self
            .projection
            .safe_rekey_target_after(&decision.stable_fp, decision.read_watermark)?
        {
            decision.stable_fp = forwarded;
            return Ok(());
        }
        let intervening = self
            .projection
            .event_seqs_for_stable_fp_after(&decision.stable_fp, decision.read_watermark)?;
        if !intervening.is_empty() {
            bail!(
                "finding {} changed after read watermark {} at event seq(s) {}; reload before deciding",
                decision.stable_fp,
                decision.read_watermark,
                intervening
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        Ok(())
    }
}
