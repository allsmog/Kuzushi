use super::{JobEventSink, ShellEvent};
use std::sync::Arc;

type RunLifecycleSubscribers = (
    kuzushi_core::run_lifecycle::CommittedItemSubscriber,
    kuzushi_core::run_lifecycle::CommittedRangeSubscriber,
    kuzushi_core::run_lifecycle::DerivativeRangeSubscriber,
    kuzushi_core::run_lifecycle::RunItemDeliveryFaultSubscriber,
);

impl JobEventSink {
    pub(crate) fn run_lifecycle_subscribers(&self, run_id: &str) -> RunLifecycleSubscribers {
        let item_sink = self.clone();
        let item_subscriber = Arc::new(
            move |item: &kuzushi_core::run_lifecycle::RunItemEnvelopeV1| {
                item_sink.send(ShellEvent::RunItem(item.clone()));
            },
        );
        let range_subscriber = durable_range_subscriber(self, run_id);
        let derivative_subscriber = derivative_range_subscriber(self, run_id);
        let fault_subscriber = delivery_fault_subscriber(self, run_id);
        (
            item_subscriber,
            range_subscriber,
            derivative_subscriber,
            fault_subscriber,
        )
    }
}

fn durable_range_subscriber(
    sink: &JobEventSink,
    run_id: &str,
) -> kuzushi_core::run_lifecycle::CommittedRangeSubscriber {
    let sink = sink.clone();
    let run_id = run_id.to_string();
    Arc::new(move |range| {
        sink.send(ShellEvent::RunItemsDurable {
            run_id: run_id.clone(),
            range,
        });
    })
}

fn derivative_range_subscriber(
    sink: &JobEventSink,
    run_id: &str,
) -> kuzushi_core::run_lifecycle::DerivativeRangeSubscriber {
    let sink = sink.clone();
    let run_id = run_id.to_string();
    Arc::new(move |range| {
        sink.send(ShellEvent::RunItemsDerivativesApplied {
            run_id: run_id.clone(),
            range,
        });
    })
}

fn delivery_fault_subscriber(
    sink: &JobEventSink,
    run_id: &str,
) -> kuzushi_core::run_lifecycle::RunItemDeliveryFaultSubscriber {
    let sink = sink.clone();
    let run_id = run_id.to_string();
    Arc::new(move |fault| {
        sink.send(ShellEvent::RunItemsDeliveryFault {
            run_id: run_id.clone(),
            fault,
        });
    })
}
