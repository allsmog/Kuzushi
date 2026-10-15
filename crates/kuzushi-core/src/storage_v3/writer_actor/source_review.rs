//! Record explicit reviewed source in the same event as its human verdict.
use super::*;
use crate::findings::ReviewSourceCapture;

impl StorageWriter {
    pub(super) fn record_source_review_decision(
        &mut self,
        mut decision: DecisionWrite,
        source: ReviewSourceCapture,
    ) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        anyhow::ensure!(
            source.schema_version == 1,
            "Unsupported reviewed source version"
        );
        anyhow::ensure!(
            source.read_watermark <= self.projection.meta()?.applied_seq,
            "Reviewed source cutoff is newer than this ledger"
        );
        self.forward_or_reject_stale_decision(&mut decision)?;
        anyhow::ensure!(
            decision.stable_fp == source.stable_fp
                && decision.finding_id == Some(source.finding_id)
                && decision.read_watermark == source.read_watermark,
            "Reviewed source no longer matches this finding generation"
        );
        let mut payload = decision.payload();
        payload["reviewedSource"] = serde_json::to_value(source)?;
        let event = self.log.append(
            decision.event_kind(),
            decision.author.clone(),
            None,
            None,
            payload,
        )?;
        self.apply_appended_event(&event)
    }
}
