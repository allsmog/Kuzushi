use super::{
    writer_derivatives::start_derivative_delivery_pump,
    writer_range_delivery::start_range_delivery_pump, CommittedItemSubscriber, CommittedRange,
    CommittedRangeSubscriber, DerivativeRangeSubscriber, RunItemDeliveryFaultSubscriber,
    WriterState,
};
use crate::run_lifecycle::{
    read_run_items, ProjectionHealth, RunItemDeliveryFailureStage, RunItemDeliveryFault,
    RunItemEnvelopeV1,
};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;

#[derive(Clone)]
pub(super) struct DeliveryPublisher {
    latest_seq: Arc<AtomicU64>,
    item_wake: SyncSender<()>,
    range_wake: Option<SyncSender<()>>,
    derivative_wake: SyncSender<()>,
}

pub(super) struct DeliverySubscribers {
    pub(super) item: Option<CommittedItemSubscriber>,
    pub(super) range: Option<CommittedRangeSubscriber>,
    pub(super) derivative: Option<DerivativeRangeSubscriber>,
    pub(super) fault: Option<RunItemDeliveryFaultSubscriber>,
}

pub(super) struct DeliveryPumps {
    pub(super) publisher: DeliveryPublisher,
    pub(super) item_thread: JoinHandle<()>,
    pub(super) range_thread: Option<JoinHandle<()>>,
    pub(super) derivative_thread: JoinHandle<()>,
}

impl WriterState {
    pub(super) fn publish_committed(&self, range: CommittedRange) {
        let Some(delivery) = self.delivery.as_ref() else {
            return;
        };
        delivery.publish(range);
    }
}

impl DeliveryPublisher {
    fn new(
        latest_seq: Arc<AtomicU64>,
        item_wake: SyncSender<()>,
        range_wake: Option<SyncSender<()>>,
        derivative_wake: SyncSender<()>,
    ) -> Self {
        Self {
            latest_seq,
            item_wake,
            range_wake,
            derivative_wake,
        }
    }

    pub(super) fn publish(&self, range: CommittedRange) {
        self.latest_seq
            .fetch_max(range.through_seq, Ordering::Release);
        let _ = self.item_wake.try_send(());
        let _ = self.derivative_wake.try_send(());
        if let Some(wake) = self.range_wake.as_ref() {
            let _ = wake.try_send(());
        }
    }
}

pub(super) fn start_delivery_pumps(
    target: PathBuf,
    run_id: String,
    initial_seq: u64,
    subscribers: DeliverySubscribers,
) -> Result<DeliveryPumps> {
    let latest_seq = Arc::new(AtomicU64::new(initial_seq));
    let (item_wake, item_thread) = start_item_delivery_pump(
        target.clone(),
        run_id.clone(),
        initial_seq,
        Arc::clone(&latest_seq),
        subscribers.item,
        subscribers.fault.clone(),
    )?;
    let (range_wake, range_thread) = start_range_delivery_pump(
        initial_seq,
        Arc::clone(&latest_seq),
        subscribers.range,
        subscribers.fault.clone(),
    )?;
    let (derivative_wake, derivative_thread) = start_derivative_delivery_pump(
        target,
        run_id,
        initial_seq,
        Arc::clone(&latest_seq),
        subscribers.derivative,
        subscribers.fault,
    )?;
    let publisher = DeliveryPublisher::new(latest_seq, item_wake, range_wake, derivative_wake);
    Ok(DeliveryPumps {
        publisher,
        item_thread,
        range_thread,
        derivative_thread,
    })
}

pub(super) fn start_item_delivery_pump(
    target: PathBuf,
    run_id: String,
    initial_seq: u64,
    latest_seq: Arc<AtomicU64>,
    subscriber: Option<CommittedItemSubscriber>,
    fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
) -> Result<(SyncSender<()>, JoinHandle<()>)> {
    let (wake, receiver) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name(format!("run-items-delivery-{run_id}"))
        .spawn(move || {
            delivery_loop(
                &target,
                &run_id,
                initial_seq,
                &latest_seq,
                &receiver,
                subscriber.as_ref(),
                fault_subscriber.as_ref(),
            )
        })
        .context("spawn run-item delivery worker")?;
    Ok((wake, thread))
}

fn delivery_loop(
    target: &Path,
    run_id: &str,
    mut applied_seq: u64,
    latest_seq: &AtomicU64,
    receiver: &Receiver<()>,
    subscriber: Option<&CommittedItemSubscriber>,
    fault_subscriber: Option<&RunItemDeliveryFaultSubscriber>,
) {
    while receiver.recv().is_ok() {
        match deliver_through(
            target,
            run_id,
            applied_seq,
            latest_seq,
            subscriber,
        ) {
            Ok(next) => applied_seq = next,
            Err(fault) => {
                report_delivery_fault(fault_subscriber, fault);
                return;
            }
        }
    }
    if let Err(fault) = deliver_through(
        target,
        run_id,
        applied_seq,
        latest_seq,
        subscriber,
    ) {
        report_delivery_fault(fault_subscriber, fault);
    }
}

fn deliver_through(
    target: &Path,
    run_id: &str,
    applied_seq: u64,
    latest_seq: &AtomicU64,
    subscriber: Option<&CommittedItemSubscriber>,
) -> std::result::Result<u64, RunItemDeliveryFault> {
    let through_seq = latest_seq.load(Ordering::Acquire);
    if through_seq <= applied_seq {
        return Ok(applied_seq);
    }
    let items = delivery_batch(target, run_id, applied_seq, through_seq)?;
    notify_item_subscriber(&items, applied_seq, through_seq, subscriber)
}

pub(super) fn delivery_batch(
    target: &Path,
    run_id: &str,
    applied_seq: u64,
    through_seq: u64,
) -> std::result::Result<Vec<RunItemEnvelopeV1>, RunItemDeliveryFault> {
    let read = read_run_items(target, run_id)
        .map_err(|_| read_stream_fault(applied_seq, through_seq, "could not read durable stream"))?
        .ok_or_else(|| read_stream_fault(applied_seq, through_seq, "durable stream is missing"))?;
    if !matches!(read.health, ProjectionHealth::Healthy) {
        return Err(read_stream_fault(
            applied_seq,
            through_seq,
            "durable stream failed integrity validation",
        ));
    }
    let items = read
        .items
        .into_iter()
        .filter(|item| item.seq > applied_seq && item.seq <= through_seq)
        .collect::<Vec<_>>();
    if items.is_empty() {
        return Err(RunItemDeliveryFault::new(
            RunItemDeliveryFailureStage::EmptyBatch,
            applied_seq,
            through_seq,
            "durable high-watermark had no deliverable items",
        ));
    }
    Ok(items)
}

fn notify_item_subscriber(
    items: &[RunItemEnvelopeV1],
    mut applied_seq: u64,
    durable_seq: u64,
    subscriber: Option<&CommittedItemSubscriber>,
) -> std::result::Result<u64, RunItemDeliveryFault> {
    let Some(subscriber) = subscriber else {
        return Ok(items.last().map_or(applied_seq, |item| item.seq));
    };
    for item in items {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| subscriber(item))).map_err(
            |_| {
                RunItemDeliveryFault::new(
                    RunItemDeliveryFailureStage::ItemSubscriber,
                    applied_seq,
                    durable_seq,
                    "committed-item subscriber panicked",
                )
            },
        )?;
        applied_seq = item.seq;
    }
    Ok(applied_seq)
}

fn read_stream_fault(applied_seq: u64, durable_seq: u64, detail: &str) -> RunItemDeliveryFault {
    RunItemDeliveryFault::new(
        RunItemDeliveryFailureStage::ReadStream,
        applied_seq,
        durable_seq,
        detail,
    )
}

pub(super) fn report_delivery_fault(
    subscriber: Option<&RunItemDeliveryFaultSubscriber>,
    fault: RunItemDeliveryFault,
) {
    let Some(subscriber) = subscriber else {
        return;
    };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| subscriber(fault)));
}

#[cfg(test)]
#[path = "writer_delivery_tests.rs"]
mod tests;
