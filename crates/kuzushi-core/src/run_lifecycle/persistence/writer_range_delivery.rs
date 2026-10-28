use super::{
    writer_delivery::report_delivery_fault, CommittedRange, CommittedRangeSubscriber,
    RunItemDeliveryFaultSubscriber,
};
use crate::run_lifecycle::{RunItemDeliveryFailureStage, RunItemDeliveryFault};
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;

pub(super) fn start_range_delivery_pump(
    initial_seq: u64,
    latest_seq: Arc<AtomicU64>,
    subscriber: Option<CommittedRangeSubscriber>,
    fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
) -> Result<(Option<SyncSender<()>>, Option<JoinHandle<()>>)> {
    let Some(subscriber) = subscriber else {
        return Ok((None, None));
    };
    let (wake, receiver) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name("run-items-range-delivery".to_string())
        .spawn(move || {
            range_delivery_loop(
                initial_seq,
                &latest_seq,
                &receiver,
                &subscriber,
                fault_subscriber.as_ref(),
            )
        })
        .context("spawn run-item range delivery worker")?;
    Ok((Some(wake), Some(thread)))
}

fn range_delivery_loop(
    mut announced_seq: u64,
    latest_seq: &AtomicU64,
    receiver: &Receiver<()>,
    subscriber: &CommittedRangeSubscriber,
    fault_subscriber: Option<&RunItemDeliveryFaultSubscriber>,
) {
    while receiver.recv().is_ok() {
        match announce_durable_range(announced_seq, latest_seq, subscriber) {
            Ok(next) => announced_seq = next,
            Err(fault) => {
                report_delivery_fault(fault_subscriber, fault);
                return;
            }
        }
    }
    if let Err(fault) = announce_durable_range(announced_seq, latest_seq, subscriber) {
        report_delivery_fault(fault_subscriber, fault);
    }
}

fn announce_durable_range(
    announced_seq: u64,
    latest_seq: &AtomicU64,
    subscriber: &CommittedRangeSubscriber,
) -> std::result::Result<u64, RunItemDeliveryFault> {
    let through_seq = latest_seq.load(Ordering::Acquire);
    if through_seq <= announced_seq {
        return Ok(announced_seq);
    }
    let range = CommittedRange {
        first_seq: announced_seq.saturating_add(1),
        through_seq,
    };
    crate::recovered_panic::catch(|| subscriber(range)).map_err(|_| {
        RunItemDeliveryFault::new(
            RunItemDeliveryFailureStage::RangeSubscriber,
            announced_seq,
            through_seq,
            "durable-range subscriber panicked",
        )
    })?;
    Ok(through_seq)
}
