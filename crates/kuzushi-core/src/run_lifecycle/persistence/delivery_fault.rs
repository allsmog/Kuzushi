use crate::run_lifecycle::SafeText;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RunItemDeliveryFailureStage {
    ReadStream,
    EmptyBatch,
    ItemSubscriber,
    RangeSubscriber,
    DerivativeReadStream,
    DerivativeEmptyBatch,
    DerivativeSubscriber,
    StorageProjection,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunItemDeliveryFault {
    pub stage: RunItemDeliveryFailureStage,
    pub applied_seq: u64,
    pub durable_seq: u64,
    pub detail: SafeText,
}

impl RunItemDeliveryFault {
    pub const fn is_derivative(&self) -> bool {
        matches!(
            self.stage,
            RunItemDeliveryFailureStage::DerivativeReadStream
                | RunItemDeliveryFailureStage::DerivativeEmptyBatch
                | RunItemDeliveryFailureStage::DerivativeSubscriber
                | RunItemDeliveryFailureStage::StorageProjection
        )
    }

    pub(super) fn new(
        stage: RunItemDeliveryFailureStage,
        applied_seq: u64,
        durable_seq: u64,
        detail: impl AsRef<str>,
    ) -> Self {
        Self {
            stage,
            applied_seq,
            durable_seq,
            detail: SafeText::operator_visible(detail),
        }
    }
}
