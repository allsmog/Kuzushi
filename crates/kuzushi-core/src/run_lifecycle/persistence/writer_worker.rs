use super::writer_coalescing::CoalescedItems;
use super::writer_commit::{
    commit_batch, prepare_batch, reply_failure, reply_success, send_unit, sync_writer,
};
use super::{PendingItem, RunItemRecord, RunItemWriterFault, WriterCommand, WriterState};
use crate::run_lifecycle::{PersistenceFailureStage, SafeText};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_BATCH_ITEMS: usize = 64;
const MAX_BATCH_WAIT: Duration = Duration::from_millis(20);

pub(super) fn writer_loop(
    mut state: WriterState,
    receiver: Receiver<WriterCommand>,
    coalesced: Arc<Mutex<CoalescedItems>>,
) {
    loop {
        match receiver.recv_timeout(MAX_BATCH_WAIT) {
            Ok(command) => {
                if handle_command(&mut state, &receiver, &coalesced, command) {
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => flush_coalesced(&mut state, &coalesced),
            Err(RecvTimeoutError::Disconnected) => {
                flush_coalesced(&mut state, &coalesced);
                return;
            }
        }
    }
}

fn handle_command(
    state: &mut WriterState,
    receiver: &Receiver<WriterCommand>,
    coalesced: &Arc<Mutex<CoalescedItems>>,
    command: WriterCommand,
) -> bool {
    match command {
        WriterCommand::Emit(record) => write_emit_batch(state, receiver, coalesced, record),
        WriterCommand::EmitAndFlush(record, reply) => {
            flush_then_write(state, coalesced, PendingItem::with_reply(record, reply));
            false
        }
        WriterCommand::Flush(reply) => {
            flush_coalesced(state, coalesced);
            send_unit(reply, sync_writer(state));
            false
        }
        WriterCommand::Shutdown(reply) => {
            flush_coalesced(state, coalesced);
            send_unit(reply, sync_writer(state));
            true
        }
    }
}

fn write_emit_batch(
    state: &mut WriterState,
    receiver: &Receiver<WriterCommand>,
    coalesced: &Arc<Mutex<CoalescedItems>>,
    record: RunItemRecord,
) -> bool {
    let (pending, deferred, disconnected) = collect_emit_batch(receiver, record);
    write_pending(state, pending);
    disconnected
        || deferred.is_some_and(|command| handle_command(state, receiver, coalesced, command))
}

fn collect_emit_batch(
    receiver: &Receiver<WriterCommand>,
    record: RunItemRecord,
) -> (Vec<PendingItem>, Option<WriterCommand>, bool) {
    let mut pending = vec![PendingItem::without_reply(record)];
    let deadline = Instant::now() + MAX_BATCH_WAIT;
    while pending.len() < MAX_BATCH_ITEMS && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(WriterCommand::Emit(record)) => pending.push(PendingItem::without_reply(record)),
            Ok(other) => return (pending, Some(other), false),
            Err(RecvTimeoutError::Timeout) => break,
            Err(RecvTimeoutError::Disconnected) => return (pending, None, true),
        }
    }
    (pending, None, false)
}

fn flush_then_write(
    state: &mut WriterState,
    coalesced: &Arc<Mutex<CoalescedItems>>,
    pending: PendingItem,
) {
    flush_coalesced(state, coalesced);
    write_pending(state, vec![pending]);
}

fn flush_coalesced(state: &mut WriterState, coalesced: &Arc<Mutex<CoalescedItems>>) {
    let mut pending = coalesced
        .lock()
        .expect("coalesced item lock poisoned")
        .drain();
    while !pending.is_empty() {
        let tail = pending.split_off(pending.len().min(MAX_BATCH_ITEMS));
        write_pending(state, pending);
        pending = tail;
    }
}

fn write_pending(state: &mut WriterState, pending: Vec<PendingItem>) {
    if let Some(fault) = unrecoverable_fault(state, &pending) {
        reply_failure(pending, fault);
        return;
    }
    let batch = match prepare_batch(state, &pending) {
        Ok(batch) => batch,
        Err(error) => {
            return fail_pending(state, pending, PersistenceFailureStage::Prepare, &error)
        }
    };
    match commit_batch(state, batch) {
        Ok(envelopes) => reply_success(pending, &envelopes),
        Err(error) => fail_pending(state, pending, error.stage(), error.error()),
    }
}

fn unrecoverable_fault<'a>(
    state: &'a WriterState,
    pending: &[PendingItem],
) -> Option<&'a RunItemWriterFault> {
    let fault = state.failure.as_ref()?;
    let reserve_recovery = fault.stage == PersistenceFailureStage::Prepare
        && fault.detail.as_str().contains("stream budget exhausted")
        && pending
            .iter()
            .all(|item| reserve_recovery_eligible_record(&item.record));
    (!reserve_recovery).then_some(fault)
}

fn fail_pending(
    state: &mut WriterState,
    pending: Vec<PendingItem>,
    stage: PersistenceFailureStage,
    error: &anyhow::Error,
) {
    let fault = writer_fault(state, stage, error);
    state.failure = Some(fault.clone());
    reply_failure(pending, &fault);
}

pub(super) fn reserve_recovery_eligible_record(record: &RunItemRecord) -> bool {
    if matches!(
        &record.item,
        crate::run_lifecycle::RunItemV1::ModelCallFinished { .. }
    ) {
        return true;
    }
    let inspection_item = matches!(
        &record.item,
        crate::run_lifecycle::RunItemV1::PlanUpdated { .. }
            | crate::run_lifecycle::RunItemV1::TaskUpdated { .. }
            | crate::run_lifecycle::RunItemV1::ToolCallFinished { .. }
            | crate::run_lifecycle::RunItemV1::TerminalOutcome { .. }
            | crate::run_lifecycle::RunItemV1::PhaseReceipt { .. }
    );
    inspection_item
        && matches!(
            record.item.status(),
            Some(crate::run_lifecycle::RunItemStatus::Partial)
                | Some(crate::run_lifecycle::RunItemStatus::Blocked)
                | Some(crate::run_lifecycle::RunItemStatus::Failed)
                | Some(crate::run_lifecycle::RunItemStatus::Canceled)
                | Some(crate::run_lifecycle::RunItemStatus::Interrupted)
        )
}

pub(super) fn writer_fault(
    state: &WriterState,
    stage: PersistenceFailureStage,
    error: &anyhow::Error,
) -> RunItemWriterFault {
    RunItemWriterFault {
        stage,
        last_durable_seq: state.next_seq.saturating_sub(1),
        detail: SafeText::operator_visible(error.to_string()),
        execution_may_have_occurred: false,
    }
}
