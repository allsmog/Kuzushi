use super::{CommittedRange, PendingItem, RunItemWriterFault, WriterReply, WriterState};
use crate::run_lifecycle::{
    RunItemEnvelopeV1, RunItemV1, MAX_RUN_ITEM_STREAM_BYTES, RUN_ITEM_CRITICAL_RESERVE_BYTES,
};
use anyhow::{Context, Result};
use std::io::Write;
use std::sync::mpsc::{self, SyncSender};

pub(super) fn prepare_batch(
    state: &WriterState,
    pending: &[PendingItem],
) -> Result<Vec<RunItemEnvelopeV1>> {
    let mut next_seq = state.next_seq;
    let mut previous_hash = state.previous_hash.clone();
    let mut envelopes = Vec::with_capacity(pending.len());
    for item in pending {
        let envelope = RunItemEnvelopeV1::from_record(
            next_seq,
            state.run_id.clone(),
            item.record.clone(),
            previous_hash,
        )?;
        previous_hash = Some(envelope.event_hash.clone());
        next_seq += 1;
        envelopes.push(envelope);
    }
    validate_stream_budget(state.bytes_written, &envelopes)?;
    Ok(envelopes)
}

pub(super) enum CommitBatchError {
    Append(anyhow::Error),
    Sync(anyhow::Error),
}

impl CommitBatchError {
    pub(super) fn stage(&self) -> crate::run_lifecycle::PersistenceFailureStage {
        match self {
            Self::Append(_) => crate::run_lifecycle::PersistenceFailureStage::Append,
            Self::Sync(_) => crate::run_lifecycle::PersistenceFailureStage::Sync,
        }
    }

    pub(super) fn error(&self) -> &anyhow::Error {
        match self {
            Self::Append(error) | Self::Sync(error) => error,
        }
    }
}

pub(super) fn commit_batch(
    state: &mut WriterState,
    envelopes: Vec<RunItemEnvelopeV1>,
) -> std::result::Result<Vec<RunItemEnvelopeV1>, CommitBatchError> {
    let bytes = serialize_batch(&envelopes).map_err(CommitBatchError::Append)?;
    state
        .file
        .write_all(&bytes)
        .context("append run-item batch")
        .map_err(CommitBatchError::Append)?;
    state
        .file
        .sync_data()
        .context("sync run-item batch")
        .map_err(CommitBatchError::Sync)?;
    commit_state(state, &envelopes, bytes.len() as u64);
    if let (Some(first), Some(last)) = (envelopes.first(), envelopes.last()) {
        state.publish_committed(CommittedRange {
            first_seq: first.seq,
            through_seq: last.seq,
        });
    }
    Ok(envelopes)
}

fn commit_state(state: &mut WriterState, envelopes: &[RunItemEnvelopeV1], bytes: u64) {
    state.bytes_written += bytes;
    if let Some(last) = envelopes.last() {
        state.next_seq = last.seq + 1;
        state.previous_hash = Some(last.event_hash.clone());
    }
}

fn serialize_batch(envelopes: &[RunItemEnvelopeV1]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for envelope in envelopes {
        serde_json::to_writer(&mut bytes, envelope).context("serialize run item")?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

pub(super) fn validate_stream_budget(current: u64, envelopes: &[RunItemEnvelopeV1]) -> Result<()> {
    let bytes = serialize_batch(envelopes)?.len() as u64;
    let projected = current
        .checked_add(bytes)
        .context("run-item stream size overflow")?;
    let limit = if envelopes.iter().all(reserve_eligible) {
        MAX_RUN_ITEM_STREAM_BYTES
    } else {
        MAX_RUN_ITEM_STREAM_BYTES - RUN_ITEM_CRITICAL_RESERVE_BYTES
    };
    anyhow::ensure!(projected <= limit, "run-item stream budget exhausted");
    Ok(())
}

fn reserve_eligible(envelope: &RunItemEnvelopeV1) -> bool {
    reserve_eligible_item(&envelope.item)
}

pub(super) fn reserve_eligible_item(item: &RunItemV1) -> bool {
    matches!(
        item,
        RunItemV1::PlanUpdated { status, .. } if status.is_terminal()
    ) || matches!(
        item,
        RunItemV1::TaskUpdated { status, .. } if status.is_terminal()
    ) || matches!(
        item,
        RunItemV1::ToolCallFinished { status, .. } if status.is_terminal()
    ) || matches!(
        item,
        RunItemV1::OperatorQuestion { .. }
            | RunItemV1::OperatorDecision { .. }
            | RunItemV1::TerminalOutcome { .. }
            | RunItemV1::PhaseReceipt { .. }
            | RunItemV1::ProgressTruncated { .. }
    )
}

pub(super) fn reply_success(pending: Vec<PendingItem>, envelopes: &[RunItemEnvelopeV1]) {
    pending
        .into_iter()
        .zip(envelopes)
        .filter_map(|(pending, envelope)| pending.reply.map(|reply| (reply, envelope.clone())))
        .for_each(|(reply, envelope)| {
            let _ = reply.send(Ok(envelope));
        });
}

pub(super) fn reply_failure(pending: Vec<PendingItem>, error: &RunItemWriterFault) {
    pending
        .into_iter()
        .filter_map(|pending| pending.reply)
        .for_each(|reply| {
            let _ = reply.send(Err(error.clone()));
        });
}

pub(super) fn send_unit(reply: SyncSender<WriterReply<()>>, result: WriterReply<()>) {
    let _ = reply.send(result);
}

pub(super) fn sync_writer(state: &mut WriterState) -> WriterReply<()> {
    if let Some(error) = state.failure.as_ref() {
        return Err(error.clone());
    }
    if let Err(error) = state.file.sync_data().context("sync run-item stream") {
        let fault = super::writer_worker::writer_fault(
            state,
            crate::run_lifecycle::PersistenceFailureStage::Flush,
            &error,
        );
        state.failure = Some(fault.clone());
        return Err(fault);
    }
    Ok(())
}

pub(super) fn receive_result<T>(
    received: std::result::Result<WriterReply<T>, mpsc::RecvError>,
    context: &str,
) -> Result<T> {
    received
        .map_err(|error| anyhow::anyhow!("{context} reply failed: {error}"))?
        .map_err(|error| anyhow::Error::new(error).context(format!("{context} failed")))
}
