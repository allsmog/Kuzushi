use super::RunObservationHandle;
use crate::run_artifacts::{TraceHandle, TraceSink};
use crate::run_lifecycle::{
    CommittedItemSubscriber, CommittedRangeSubscriber, DerivativeRangeSubscriber,
    RunItemDeliveryFaultSubscriber,
};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;

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

    pub fn with_trace_sink(
        target: impl Into<PathBuf>,
        run_id: impl Into<String>,
        sink: Arc<dyn TraceSink>,
        initial_step_number: usize,
        subscriber: Option<CommittedItemSubscriber>,
    ) -> Result<Self> {
        Self::with_trace_sink_and_subscribers(
            target,
            run_id,
            sink,
            initial_step_number,
            subscriber,
            None,
        )
    }

    pub fn with_trace_sink_and_subscribers(
        target: impl Into<PathBuf>,
        run_id: impl Into<String>,
        sink: Arc<dyn TraceSink>,
        initial_step_number: usize,
        subscriber: Option<CommittedItemSubscriber>,
        range_subscriber: Option<CommittedRangeSubscriber>,
    ) -> Result<Self> {
        Self::with_trace_sink_and_delivery_subscribers(
            target,
            run_id,
            sink,
            initial_step_number,
            subscriber,
            range_subscriber,
            None,
        )
    }

    pub fn with_trace_sink_and_delivery_subscribers(
        target: impl Into<PathBuf>,
        run_id: impl Into<String>,
        sink: Arc<dyn TraceSink>,
        initial_step_number: usize,
        subscriber: Option<CommittedItemSubscriber>,
        range_subscriber: Option<CommittedRangeSubscriber>,
        fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
    ) -> Result<Self> {
        Self::with_trace_sink_and_derivative_delivery_subscriber(
            target,
            run_id,
            sink,
            initial_step_number,
            subscriber,
            range_subscriber,
            None,
            fault_subscriber,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_trace_sink_and_derivative_delivery_subscriber(
        target: impl Into<PathBuf>,
        run_id: impl Into<String>,
        sink: Arc<dyn TraceSink>,
        initial_step_number: usize,
        subscriber: Option<CommittedItemSubscriber>,
        range_subscriber: Option<CommittedRangeSubscriber>,
        derivative_subscriber: Option<DerivativeRangeSubscriber>,
        fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
    ) -> Result<Self> {
        let target = target.into();
        let run_id = run_id.into();
        let writer = crate::run_lifecycle::RunItemWriter::open_with_derivative_delivery_subscriber(
            &target,
            &run_id,
            subscriber,
            range_subscriber,
            derivative_subscriber,
            fault_subscriber,
        )?;
        let trace = TraceHandle::with_initial_step_number_and_observation(
            sink,
            initial_step_number,
            writer,
        );
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
