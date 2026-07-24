use super::RunObservationHandle;
use crate::run_artifacts::TraceHandle;
use crate::run_lifecycle::{
    CommittedItemSubscriber, CommittedRangeSubscriber, DerivativeRangeSubscriber,
    RunItemDeliveryFaultSubscriber,
};
use anyhow::Result;
use std::path::PathBuf;

impl RunObservationHandle {
    pub fn jsonl(target: impl Into<PathBuf>, run_id: impl Into<String>) -> Result<Self> {
        Self::jsonl_with_subscriber(target, run_id, None)
    }

    pub fn jsonl_with_subscriber(
        target: impl Into<PathBuf>,
        run_id: impl Into<String>,
        subscriber: Option<CommittedItemSubscriber>,
    ) -> Result<Self> {
        Self::jsonl_with_subscribers(target, run_id, subscriber, None)
    }

    pub fn jsonl_with_subscribers(
        target: impl Into<PathBuf>,
        run_id: impl Into<String>,
        subscriber: Option<CommittedItemSubscriber>,
        range_subscriber: Option<CommittedRangeSubscriber>,
    ) -> Result<Self> {
        Self::jsonl_with_delivery_subscribers(target, run_id, subscriber, range_subscriber, None)
    }

    pub fn jsonl_with_delivery_subscribers(
        target: impl Into<PathBuf>,
        run_id: impl Into<String>,
        subscriber: Option<CommittedItemSubscriber>,
        range_subscriber: Option<CommittedRangeSubscriber>,
        fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
    ) -> Result<Self> {
        Self::jsonl_with_derivative_delivery_subscriber(
            target,
            run_id,
            subscriber,
            range_subscriber,
            None,
            fault_subscriber,
        )
    }

    pub fn jsonl_with_derivative_delivery_subscriber(
        target: impl Into<PathBuf>,
        run_id: impl Into<String>,
        subscriber: Option<CommittedItemSubscriber>,
        range_subscriber: Option<CommittedRangeSubscriber>,
        derivative_subscriber: Option<DerivativeRangeSubscriber>,
        fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
    ) -> Result<Self> {
        let trace = TraceHandle::observed_jsonl_with_derivative_delivery_subscriber(
            target,
            run_id,
            subscriber,
            range_subscriber,
            derivative_subscriber,
            fault_subscriber,
        )?;
        Ok(Self::from_trace(trace))
    }

    pub(crate) fn from_trace(trace: TraceHandle) -> Self {
        Self {
            trace,
            plan_item_id: None,
            plan_revision: 0,
            task_id: None,
            task_item_id: None,
            task_title: None,
            parent_item_id: None,
            attempt_id: None,
            phase: None,
        }
    }
}
