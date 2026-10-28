use super::{
    super::stream_reader::{parse_record, RunItemStreamReader},
    writer_derivatives::start_derivative_delivery_pump,
    writer_range_delivery::start_range_delivery_pump, CommittedItemSubscriber, CommittedRange,
    CommittedRangeSubscriber, DerivativeRangeSubscriber, RunItemDeliveryFaultSubscriber,
    WriterState,
};
use crate::run_lifecycle::{
    application::{apply_envelope, RunProjection},
    RunId, RunItemDeliveryFailureStage, RunItemDeliveryFault, RunItemEnvelopeV1,
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

pub(super) struct DeliveryCursor {
    stream: RunItemStreamReader,
    projection: RunProjection,
    #[cfg(test)]
    post_read_hook: Option<Arc<dyn Fn() + Send + Sync>>,
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
    let cursor = DeliveryCursor::open(&target, &run_id, initial_seq)?;
    let thread = std::thread::Builder::new()
        .name(format!("run-items-delivery-{run_id}"))
        .spawn(move || {
            delivery_loop(
                cursor,
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
    mut cursor: DeliveryCursor,
    latest_seq: &AtomicU64,
    receiver: &Receiver<()>,
    subscriber: Option<&CommittedItemSubscriber>,
    fault_subscriber: Option<&RunItemDeliveryFaultSubscriber>,
) {
    while receiver.recv().is_ok() {
        match deliver_through(&mut cursor, latest_seq, subscriber) {
            Ok(_) => {}
            Err(fault) => {
                report_delivery_fault(fault_subscriber, fault);
                return;
            }
        }
    }
    if let Err(fault) = deliver_through(&mut cursor, latest_seq, subscriber) {
        report_delivery_fault(fault_subscriber, fault);
    }
}

fn deliver_through(
    cursor: &mut DeliveryCursor,
    latest_seq: &AtomicU64,
    subscriber: Option<&CommittedItemSubscriber>,
) -> std::result::Result<u64, RunItemDeliveryFault> {
    let applied_seq = cursor.applied_seq();
    let through_seq = latest_seq.load(Ordering::Acquire);
    if through_seq <= applied_seq {
        return Ok(applied_seq);
    }
    let items = cursor.read_through(through_seq)?;
    notify_item_subscriber(&items, applied_seq, through_seq, subscriber)
}

impl DeliveryCursor {
    pub(super) fn open(target: &Path, run_id: &str, applied_seq: u64) -> Result<Self> {
        let run_id = RunId::parse(run_id)?;
        let path = crate::run_artifacts::checked_run_artifact_path(
            target,
            run_id.as_str(),
            "items.jsonl",
        )?;
        let stream = RunItemStreamReader::open_within(target, &path)?
            .with_context(|| format!("durable stream is missing: {}", path.display()))?;
        let projection = RunProjection {
            run_id: Some(run_id),
            ..RunProjection::default()
        };
        let mut cursor = Self {
            stream,
            projection,
            #[cfg(test)]
            post_read_hook: None,
        };
        cursor.consume_committed_prefix(applied_seq)?;
        cursor.stream.verify_path_unchanged()?;
        Ok(cursor)
    }

    pub(super) fn applied_seq(&self) -> u64 {
        self.projection.last_committed_seq
    }

    pub(super) fn read_through(
        &mut self,
        through_seq: u64,
    ) -> std::result::Result<Vec<RunItemEnvelopeV1>, RunItemDeliveryFault> {
        let applied_seq = self.applied_seq();
        let stream_checkpoint = self.stream.checkpoint();
        let projection_checkpoint = self.projection.clone();
        let result = self.read_verified_batch(applied_seq, through_seq);
        if result.is_ok() {
            return result;
        }
        self.projection = projection_checkpoint;
        self.stream.restore(stream_checkpoint).map_err(|error| {
            read_stream_fault(
                applied_seq,
                through_seq,
                format!("delivery cursor rollback failed: {error}"),
            )
        })?;
        result
    }

    fn read_verified_batch(
        &mut self,
        applied_seq: u64,
        through_seq: u64,
    ) -> std::result::Result<Vec<RunItemEnvelopeV1>, RunItemDeliveryFault> {
        self.verify_stream(applied_seq, through_seq)?;
        let items = self.read_batch(applied_seq, through_seq)?;
        #[cfg(test)]
        if let Some(hook) = self.post_read_hook.as_ref() {
            hook();
        }
        self.verify_stream(applied_seq, through_seq)?;
        Ok(items)
    }

    #[cfg(test)]
    fn records_read(&self) -> usize {
        self.stream.records_read()
    }

    #[cfg(test)]
    pub(super) fn set_post_read_hook(&mut self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.post_read_hook = Some(hook);
    }

    fn consume_committed_prefix(&mut self, through_seq: u64) -> Result<()> {
        while self.applied_seq() < through_seq {
            let item = self.next_item()?.context("durable stream ended before committed prefix")?;
            anyhow::ensure!(item.seq <= through_seq, "durable stream sequence exceeded prefix");
        }
        Ok(())
    }

    fn read_batch(
        &mut self,
        applied_seq: u64,
        through_seq: u64,
    ) -> std::result::Result<Vec<RunItemEnvelopeV1>, RunItemDeliveryFault> {
        let mut items = Vec::new();
        while self.applied_seq() < through_seq {
            let item = self.next_item().map_err(|error| {
                read_stream_fault(applied_seq, through_seq, error.to_string())
            })?;
            let Some(item) = item else {
                return Err(incomplete_batch_fault(applied_seq, through_seq, items.is_empty()));
            };
            items.push(item);
        }
        Ok(items)
    }

    fn next_item(&mut self) -> Result<Option<RunItemEnvelopeV1>> {
        let Some(record) = self.stream.next_record()? else {
            return Ok(None);
        };
        let item = parse_record(record).map_err(anyhow::Error::msg)?;
        apply_envelope(&mut self.projection, item.clone())?;
        self.projection.timeline.clear();
        self.projection.committed_event_hashes.clear();
        Ok(Some(item))
    }

    fn verify_stream(
        &self,
        applied_seq: u64,
        through_seq: u64,
    ) -> std::result::Result<(), RunItemDeliveryFault> {
        self.stream.verify_path_unchanged().map_err(|error| {
            read_stream_fault(applied_seq, through_seq, error.to_string())
        })
    }
}

#[cfg(test)]
pub(super) fn delivery_batch(
    target: &Path,
    run_id: &str,
    applied_seq: u64,
    through_seq: u64,
) -> std::result::Result<Vec<RunItemEnvelopeV1>, RunItemDeliveryFault> {
    let mut cursor = DeliveryCursor::open(target, run_id, applied_seq).map_err(|error| {
        read_stream_fault(applied_seq, through_seq, error.to_string())
    })?;
    cursor.read_through(through_seq)
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
        crate::recovered_panic::catch(|| subscriber(item)).map_err(|_| {
            RunItemDeliveryFault::new(
                RunItemDeliveryFailureStage::ItemSubscriber,
                applied_seq,
                durable_seq,
                "committed-item subscriber panicked",
            )
        })?;
        applied_seq = item.seq;
    }
    Ok(applied_seq)
}

fn incomplete_batch_fault(
    applied_seq: u64,
    durable_seq: u64,
    empty: bool,
) -> RunItemDeliveryFault {
    let stage = if empty {
        RunItemDeliveryFailureStage::EmptyBatch
    } else {
        RunItemDeliveryFailureStage::ReadStream
    };
    RunItemDeliveryFault::new(
        stage,
        applied_seq,
        durable_seq,
        "durable stream ended before its published high-watermark",
    )
}

fn read_stream_fault(
    applied_seq: u64,
    durable_seq: u64,
    detail: impl AsRef<str>,
) -> RunItemDeliveryFault {
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
    let _ = crate::recovered_panic::catch(|| subscriber(fault));
}

#[cfg(test)]
#[path = "writer_delivery_tests.rs"]
mod tests;
