use super::{
    writer_delivery::{report_delivery_fault, DeliveryCursor},
    CommittedRange, DerivativeRangeSubscriber, RunItemDeliveryFaultSubscriber,
};
use crate::run_lifecycle::{
    RunItemDeliveryFailureStage, RunItemDeliveryFault, RunItemEnvelopeV1, RunItemStatus, RunItemV1,
};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;

pub(super) type DerivativeProjector = Arc<
    dyn Fn(&Path, &str, &[RunItemEnvelopeV1], u64) -> Vec<RunItemDeliveryFault>
        + Send
        + Sync
        + 'static,
>;

struct DerivativePump {
    target: PathBuf,
    run_id: String,
    latest_seq: Arc<AtomicU64>,
    subscriber: Option<DerivativeRangeSubscriber>,
    fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
    projector: DerivativeProjector,
    cursor: DeliveryCursor,
    pending: Option<PendingDerivativeBatch>,
}

struct PendingDerivativeBatch {
    through_seq: u64,
    items: Vec<RunItemEnvelopeV1>,
}

pub(super) fn start_derivative_delivery_pump(
    target: PathBuf,
    run_id: String,
    initial_durable_seq: u64,
    latest_seq: Arc<AtomicU64>,
    subscriber: Option<DerivativeRangeSubscriber>,
    fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
) -> Result<(SyncSender<()>, JoinHandle<()>)> {
    start_derivative_delivery_pump_with(
        target,
        run_id,
        initial_durable_seq,
        latest_seq,
        subscriber,
        fault_subscriber,
        Arc::new(deliver_committed_derivatives),
    )
}

pub(super) fn start_derivative_delivery_pump_with(
    target: PathBuf,
    run_id: String,
    initial_durable_seq: u64,
    latest_seq: Arc<AtomicU64>,
    subscriber: Option<DerivativeRangeSubscriber>,
    fault_subscriber: Option<RunItemDeliveryFaultSubscriber>,
    projector: DerivativeProjector,
) -> Result<(SyncSender<()>, JoinHandle<()>)> {
    let (wake, receiver) = mpsc::sync_channel(1);
    let cursor = DeliveryCursor::open(&target, &run_id, 0)?;
    let pump = DerivativePump {
        target,
        run_id: run_id.clone(),
        latest_seq,
        subscriber,
        fault_subscriber,
        projector,
        cursor,
        pending: None,
    };
    let thread = std::thread::Builder::new()
        .name(format!("run-items-derivatives-{run_id}"))
        .spawn(move || {
            let mut pump = pump;
            pump.run(&receiver)
        })
        .context("spawn run-item derivative delivery worker")?;
    if initial_durable_seq > 0 {
        let _ = wake.try_send(());
    }
    Ok((wake, thread))
}

impl DerivativePump {
    fn run(&mut self, receiver: &Receiver<()>) {
        let mut applied_seq = 0;
        while receiver.recv().is_ok() {
            applied_seq = self.attempt(applied_seq);
        }
        let _ = self.attempt(applied_seq);
    }

    fn attempt(&mut self, mut applied_seq: u64) -> u64 {
        loop {
            match self.deliver_next(applied_seq) {
                Ok(Some(next)) => applied_seq = next,
                Ok(None) => return applied_seq,
                Err(fault) => {
                    report_delivery_fault(self.fault_subscriber.as_ref(), fault);
                    return applied_seq;
                }
            }
        }
    }

    fn deliver_next(
        &mut self,
        applied_seq: u64,
    ) -> std::result::Result<Option<u64>, RunItemDeliveryFault> {
        let through_seq = self.latest_seq.load(Ordering::Acquire);
        if through_seq <= applied_seq && self.pending.is_none() {
            return Ok(None);
        }
        self.prepare_pending(applied_seq, through_seq)?;
        let pending = self.pending.as_ref().expect("pending batch is prepared");
        let faults = (self.projector)(&self.target, &self.run_id, &pending.items, applied_seq);
        reject_derivative_faults(faults, self.fault_subscriber.as_ref())?;
        notify_derivative_subscriber(applied_seq, pending.through_seq, self.subscriber.as_ref())?;
        let applied = pending.through_seq;
        self.pending = None;
        Ok(Some(applied))
    }

    fn prepare_pending(
        &mut self,
        applied_seq: u64,
        through_seq: u64,
    ) -> std::result::Result<(), RunItemDeliveryFault> {
        if let Some(pending) = self.pending.as_mut() {
            if through_seq > pending.through_seq {
                let mut items = self.cursor.read_through(through_seq).map_err(|fault| {
                    derivative_read_fault(fault, applied_seq, through_seq)
                })?;
                pending.items.append(&mut items);
                pending.through_seq = through_seq;
            }
            return Ok(());
        }
        let items = self.cursor.read_through(through_seq).map_err(|fault| {
            derivative_read_fault(fault, applied_seq, through_seq)
        })?;
        self.pending = Some(PendingDerivativeBatch { through_seq, items });
        Ok(())
    }
}

fn derivative_read_fault(
    fault: RunItemDeliveryFault,
    applied_seq: u64,
    through_seq: u64,
) -> RunItemDeliveryFault {
    let stage = match fault.stage {
        RunItemDeliveryFailureStage::EmptyBatch => RunItemDeliveryFailureStage::DerivativeEmptyBatch,
        _ => RunItemDeliveryFailureStage::DerivativeReadStream,
    };
    RunItemDeliveryFault::new(stage, applied_seq, through_seq, fault.detail.as_str())
}

fn reject_derivative_faults(
    mut faults: Vec<RunItemDeliveryFault>,
    subscriber: Option<&RunItemDeliveryFaultSubscriber>,
) -> std::result::Result<(), RunItemDeliveryFault> {
    if faults.is_empty() {
        return Ok(());
    }
    let first = faults.remove(0);
    for fault in faults {
        report_delivery_fault(subscriber, fault);
    }
    Err(first)
}

fn notify_derivative_subscriber(
    applied_seq: u64,
    through_seq: u64,
    subscriber: Option<&DerivativeRangeSubscriber>,
) -> std::result::Result<(), RunItemDeliveryFault> {
    let Some(subscriber) = subscriber else {
        return Ok(());
    };
    let range = CommittedRange {
        first_seq: applied_seq.saturating_add(1),
        through_seq,
    };
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| subscriber(range))).map_err(|_| {
        RunItemDeliveryFault::new(
            RunItemDeliveryFailureStage::DerivativeSubscriber,
            applied_seq,
            through_seq,
            "derivative-range subscriber panicked",
        )
    })
}

pub(super) fn deliver_committed_derivatives(
    target: &Path,
    run_id: &str,
    items: &[RunItemEnvelopeV1],
    applied_seq: u64,
) -> Vec<RunItemDeliveryFault> {
    let durable_seq = items.last().map_or(applied_seq, |item| item.seq);
    let mut faults = compatibility_faults(target, run_id, items, applied_seq, durable_seq);
    faults.extend(bridge_terminal_items(
        target,
        run_id,
        items,
        applied_seq,
        durable_seq,
    ));
    faults
}

fn compatibility_faults(
    target: &Path,
    run_id: &str,
    items: &[RunItemEnvelopeV1],
    applied_seq: u64,
    durable_seq: u64,
) -> Vec<RunItemDeliveryFault> {
    let Err(error) = crate::run_artifacts::append_compat_run_item_events(target, run_id, items)
    else {
        return Vec::new();
    };
    vec![RunItemDeliveryFault::new(
        RunItemDeliveryFailureStage::CompatibilityProjection,
        applied_seq,
        durable_seq,
        format!("compatibility event projection failed: {error}"),
    )]
}

fn bridge_terminal_items(
    target: &Path,
    run_id: &str,
    items: &[RunItemEnvelopeV1],
    applied_seq: u64,
    durable_seq: u64,
) -> Vec<RunItemDeliveryFault> {
    items
        .iter()
        .filter_map(|item| terminal_storage_fault(target, run_id, item, applied_seq, durable_seq))
        .collect()
}

fn terminal_storage_fault(
    target: &Path,
    run_id: &str,
    item: &RunItemEnvelopeV1,
    applied_seq: u64,
    durable_seq: u64,
) -> Option<RunItemDeliveryFault> {
    let RunItemV1::TerminalOutcome { status, .. } = &item.item else {
        return None;
    };
    bridge_terminal_item(target, run_id, item, *status)
        .err()
        .map(|error| {
            RunItemDeliveryFault::new(
                RunItemDeliveryFailureStage::StorageProjection,
                applied_seq,
                durable_seq,
                format!("terminal storage projection failed: {error}"),
            )
        })
}

fn bridge_terminal_item(
    target: &Path,
    run_id: &str,
    item: &RunItemEnvelopeV1,
    status: RunItemStatus,
) -> Result<()> {
    use crate::storage_v3::writer_actor::{
        DecisionCommand, RunLifecycleWrite, StorageWriterActor, WriterCommand,
    };
    let workspace = crate::workspace::WorkspaceTarget::new(target)?;
    StorageWriterActor::commit_blocking(
        workspace.event_log_dir(),
        workspace.findings_db_path(),
        WriterCommand::Decision(DecisionCommand::RecordRunLifecycle(RunLifecycleWrite {
            event_kind: terminal_event_kind(status),
            run_id: run_id.to_string(),
            target: Some(target.display().to_string()),
            status: status.label().to_string(),
            findings_count: None,
            terminal_item_hash: Some(item.event_hash.clone()),
            actor: "run-lifecycle".to_string(),
        })),
    )?;
    Ok(())
}

fn terminal_event_kind(status: RunItemStatus) -> crate::event_log::EventKind {
    if matches!(status, RunItemStatus::Completed | RunItemStatus::Skipped) {
        crate::event_log::EventKind::RunCompleted
    } else {
        crate::event_log::EventKind::RunFailed
    }
}

#[cfg(test)]
#[path = "writer_derivatives_tests.rs"]
mod tests;
