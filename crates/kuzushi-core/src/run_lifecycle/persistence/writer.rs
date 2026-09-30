use super::super::{
    PersistenceClass, RunId, RunItemEnvelopeV1, RunItemPersistencePolicy, RunItemRecord,
};
use super::RunItemWriterFault;
use anyhow::{Context, Result};
use std::fs::File;
use std::path::Path;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub(super) const WRITER_CAPACITY: usize = 2_048;

#[path = "writer_coalescing.rs"]
mod writer_coalescing;
#[path = "writer_commit.rs"]
mod writer_commit;
#[path = "writer_delivery.rs"]
mod writer_delivery;
#[path = "writer_derivatives.rs"]
mod writer_derivatives;
#[path = "writer_model_reserve.rs"]
mod writer_model_reserve;
#[path = "writer_open.rs"]
mod writer_open;
#[path = "writer_range_delivery.rs"]
mod writer_range_delivery;
#[path = "writer_shutdown.rs"]
mod writer_shutdown;
#[path = "writer_worker.rs"]
mod writer_worker;
use writer_coalescing::CoalescedItems;
use writer_commit::receive_result;
use writer_delivery::{
    start_delivery_pumps, DeliveryPublisher, DeliveryPumps, DeliverySubscribers,
};
use writer_open::open_writer_state;
use writer_worker::writer_loop;

pub type CommittedItemSubscriber = Arc<dyn Fn(&RunItemEnvelopeV1) + Send + Sync + 'static>;
pub type CommittedRangeSubscriber = Arc<dyn Fn(CommittedRange) + Send + Sync + 'static>;
pub type DerivativeRangeSubscriber = Arc<dyn Fn(CommittedRange) + Send + Sync + 'static>;
pub type RunItemDeliveryFaultSubscriber =
    Arc<dyn Fn(super::RunItemDeliveryFault) + Send + Sync + 'static>;

type WriterReply<T> = std::result::Result<T, RunItemWriterFault>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommittedRange {
    pub first_seq: u64,
    pub through_seq: u64,
}

#[derive(Clone)]
pub struct RunItemWriter {
    sender: SyncSender<WriterCommand>,
    coalesced: Arc<Mutex<CoalescedItems>>,
    thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    delivery_thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    range_delivery_thread: Arc<Mutex<Option<JoinHandle<()>>>>,
    derivative_delivery_thread: Arc<Mutex<Option<JoinHandle<()>>>>,
}

enum WriterCommand {
    Emit(RunItemRecord),
    EmitAndFlush(RunItemRecord, SyncSender<WriterReply<RunItemEnvelopeV1>>),
    Flush(SyncSender<WriterReply<()>>),
    Shutdown(SyncSender<WriterReply<()>>),
}

pub(super) struct PendingItem {
    pub(super) record: RunItemRecord,
    pub(super) reply: Option<SyncSender<WriterReply<RunItemEnvelopeV1>>>,
}

impl PendingItem {
    fn without_reply(record: RunItemRecord) -> Self {
        Self {
            record,
            reply: None,
        }
    }

    fn with_reply(
        record: RunItemRecord,
        reply: SyncSender<WriterReply<RunItemEnvelopeV1>>,
    ) -> Self {
        Self {
            record,
            reply: Some(reply),
        }
    }
}

struct WriterState {
    run_id: RunId,
    file: File,
    next_seq: u64,
    previous_hash: Option<String>,
    bytes_written: u64,
    model_receipts: writer_model_reserve::ModelReceiptReserve,
    delivery: Option<DeliveryPublisher>,
    failure: Option<RunItemWriterFault>,
    _lock: crate::file_lock::ExclusiveFileLock,
}

impl RunItemWriter {
    pub fn open(
        target: impl AsRef<Path>,
        run_id: &str,
        subscriber: Option<CommittedItemSubscriber>,
    ) -> Result<Self> {
        Self::open_with_subscribers(target, run_id, subscriber, None)
    }

    pub fn open_with_subscribers(
        target: impl AsRef<Path>,
        run_id: &str,
        subscriber: Option<CommittedItemSubscriber>,
        range_subscriber: Option<CommittedRangeSubscriber>,
    ) -> Result<Self> {
        Self::open_with_delivery_subscribers(target, run_id, subscriber, range_subscriber, None)
    }

    pub fn open_with_delivery_subscribers(
        target: impl AsRef<Path>,
        run_id: &str,
        subscriber: Option<CommittedItemSubscriber>,
        range_subscriber: Option<CommittedRangeSubscriber>,
        delivery_fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
    ) -> Result<Self> {
        Self::open_with_derivative_delivery_subscriber(
            target,
            run_id,
            subscriber,
            range_subscriber,
            None,
            delivery_fault_subscriber,
        )
    }

    pub fn open_with_derivative_delivery_subscriber(
        target: impl AsRef<Path>,
        run_id: &str,
        subscriber: Option<CommittedItemSubscriber>,
        range_subscriber: Option<CommittedRangeSubscriber>,
        derivative_subscriber: Option<DerivativeRangeSubscriber>,
        delivery_fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
    ) -> Result<Self> {
        Self::open_inner(
            target.as_ref(),
            run_id,
            subscriber,
            range_subscriber,
            derivative_subscriber,
            delivery_fault_subscriber,
            None,
        )
    }

    #[cfg(test)]
    fn open_with_accounted_bytes_for_test(
        target: impl AsRef<Path>,
        run_id: &str,
        accounted_bytes: u64,
    ) -> Result<Self> {
        Self::open_inner(
            target.as_ref(),
            run_id,
            None,
            None,
            None,
            None,
            Some(accounted_bytes),
        )
    }

    fn open_inner(
        target: &Path,
        run_id: &str,
        subscriber: Option<CommittedItemSubscriber>,
        range_subscriber: Option<CommittedRangeSubscriber>,
        derivative_subscriber: Option<DerivativeRangeSubscriber>,
        delivery_fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
        accounted_bytes: Option<u64>,
    ) -> Result<Self> {
        let mut state = open_writer_state(target, run_id)?;
        if let Some(accounted_bytes) = accounted_bytes {
            state.bytes_written = accounted_bytes;
        }
        let pumps = start_delivery_pumps(
            target.to_path_buf(),
            run_id.to_string(),
            state.next_seq.saturating_sub(1),
            DeliverySubscribers {
                item: subscriber,
                range: range_subscriber,
                derivative: derivative_subscriber,
                fault: delivery_fault_subscriber,
            },
        )?;
        Self::spawn_writer(state, pumps, run_id)
    }

    fn spawn_writer(mut state: WriterState, pumps: DeliveryPumps, run_id: &str) -> Result<Self> {
        let DeliveryPumps {
            publisher,
            item_thread,
            range_thread,
            derivative_thread,
        } = pumps;
        state.delivery = Some(publisher);
        let (sender, receiver) = mpsc::sync_channel(WRITER_CAPACITY);
        let coalesced = Arc::new(Mutex::new(CoalescedItems::default()));
        let worker_coalesced = Arc::clone(&coalesced);
        let thread = std::thread::Builder::new()
            .name(format!("run-items-{run_id}"))
            .spawn(move || writer_loop(state, receiver, worker_coalesced))
            .context("spawn run-item writer")?;
        Ok(Self {
            sender,
            coalesced,
            thread: Arc::new(Mutex::new(Some(thread))),
            delivery_thread: Arc::new(Mutex::new(Some(item_thread))),
            range_delivery_thread: Arc::new(Mutex::new(range_thread)),
            derivative_delivery_thread: Arc::new(Mutex::new(Some(derivative_thread))),
        })
    }

    pub fn emit(&self, record: RunItemRecord) -> Result<()> {
        if matches!(
            record.item,
            crate::run_lifecycle::RunItemV1::ModelCallStarted { .. }
                | crate::run_lifecycle::RunItemV1::ModelCallFinished { .. }
        ) {
            return self.emit_and_flush(record).map(|_| ());
        }
        RunItemPersistencePolicy::validate(&record.item)?;
        anyhow::ensure!(
            RunItemPersistencePolicy::class(&record.item) == PersistenceClass::Lossless,
            "coalescible item must use emit_coalescible"
        );
        self.sender
            .send(WriterCommand::Emit(record))
            .context("run-item writer stopped")
    }

    pub fn emit_coalescible(&self, record: RunItemRecord) -> Result<()> {
        RunItemPersistencePolicy::validate(&record.item)?;
        anyhow::ensure!(
            RunItemPersistencePolicy::class(&record.item) == PersistenceClass::Coalescible,
            "lossless item cannot use coalescible lane"
        );
        let mut state = self.coalesced.lock().expect("coalesced item lock poisoned");
        state.insert(record)
    }

    pub fn emit_and_flush(&self, record: RunItemRecord) -> Result<RunItemEnvelopeV1> {
        RunItemPersistencePolicy::validate(&record.item)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(WriterCommand::EmitAndFlush(record, sender))
            .context("run-item writer stopped")?;
        receive_result(receiver.recv(), "terminal run item")
    }

    pub fn flush(&self) -> Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(WriterCommand::Flush(sender))
            .context("run-item writer stopped")?;
        receive_result(receiver.recv(), "run-item flush")
    }
}

#[cfg(test)]
#[path = "writer_characterization.rs"]
mod characterization_tests;

#[cfg(test)]
#[path = "writer_tests.rs"]
mod tests;
