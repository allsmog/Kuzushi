use super::*;
use crate::run_lifecycle::{
    read_run_items, ModelUsage, OperationFingerprint, ProjectionHealth, RunCallId, RunId,
    RunItemRecord, RunItemSource, RunItemStatus, RunItemWriter, SafeText, WorkflowContinuation,
    RUN_ITEM_CRITICAL_RESERVE_BYTES,
};
use crate::runtime::{RuntimeCost, RuntimeCostReport};

fn start(item_id: RunItemId, call_id: RunCallId) -> RunItemRecord {
    RunItemRecord::new(
        item_id,
        RunItemSource::Runtime,
        RunItemV1::ModelCallStarted {
            provider: SafeText::operator_visible("provider"),
            model: SafeText::operator_visible("provider:model"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"model-receipt"),
        },
    )
    .with_call(call_id)
}

fn finish(item_id: RunItemId, call_id: RunCallId) -> RunItemRecord {
    RunItemRecord::new(
        item_id,
        RunItemSource::Runtime,
        RunItemV1::ModelCallFinished {
            provider: SafeText::operator_visible("provider"),
            model: SafeText::operator_visible("provider:model"),
            status: RunItemStatus::Completed,
            latency_ms: 15,
            usage: ModelUsage {
                input_tokens: Some(19),
                output_tokens: Some(7),
            },
            cost: RuntimeCostReport::known(RuntimeCost::from_usd(0.75, "test").unwrap()),
            error_class: None,
            failure: None,
        },
    )
    .with_call(call_id)
}

fn terminal() -> RunItemRecord {
    RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Workflow,
        RunItemV1::TerminalOutcome {
            status: RunItemStatus::Partial,
            summary: SafeText::operator_visible("stream capacity exhausted"),
            cost: RuntimeCostReport::known(RuntimeCost::from_usd(0.75, "test").unwrap()),
            continuation: WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("inspect durable receipt"),
            },
        },
    )
}

fn envelope(record: RunItemRecord) -> RunItemEnvelopeV1 {
    RunItemEnvelopeV1::from_record(1, RunId::parse("reserve-test").unwrap(), record, None).unwrap()
}

#[test]
fn admission_reserves_every_in_flight_receipt_and_a_terminal_record() {
    let mut reserve = ModelReceiptReserve::default();
    let mut starts = Vec::new();
    for _ in 0..MAX_IN_FLIGHT_MODEL_CALLS {
        let item = envelope(start(RunItemId::new(), RunCallId::new()));
        reserve.validate_batch(1_000, &[item.clone()]).unwrap();
        reserve.observe(&item);
        starts.push(item);
    }
    let ninth = envelope(start(RunItemId::new(), RunCallId::new()));
    assert!(reserve.validate_batch(1_000, &[ninth]).is_err());
    let required = (MAX_IN_FLIGHT_MODEL_CALLS as u64 + 1) * RECEIPT_BYTES;
    reserve
        .validate_batch(MAX_RUN_ITEM_STREAM_BYTES - required, &[])
        .unwrap();
    assert!(reserve
        .validate_batch(MAX_RUN_ITEM_STREAM_BYTES - required + 1, &[])
        .is_err());
    let first = &starts[0];
    let done = envelope(finish(first.item_id, first.call_id.unwrap()));
    reserve
        .validate_batch(
            MAX_RUN_ITEM_STREAM_BYTES - required + RECEIPT_BYTES,
            &[done],
        )
        .unwrap();
}

#[test]
fn paid_model_completion_survives_saturation_and_replays_with_cost_and_usage() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("model-reserve");
    let item_id = RunItemId::new();
    let call_id = RunCallId::new();
    let writer = RunItemWriter::open(target.path(), &run_id, None).unwrap();
    writer.emit_and_flush(start(item_id, call_id)).unwrap();
    writer.shutdown().unwrap();
    // Reopening also proves outstanding receipt credits are reconstructed.
    let writer = RunItemWriter::open_with_accounted_bytes_for_test(
        target.path(),
        &run_id,
        MAX_RUN_ITEM_STREAM_BYTES - RUN_ITEM_CRITICAL_RESERVE_BYTES,
    )
    .unwrap();
    assert!(writer
        .emit_and_flush(start(RunItemId::new(), RunCallId::new()))
        .is_err());
    writer.emit(finish(item_id, call_id)).unwrap();
    writer.emit_and_flush(terminal()).unwrap();
    assert!(
        writer.shutdown().is_err(),
        "the run must retain its degraded state"
    );
    assert_replayed_receipt(target.path(), &run_id);
}

fn assert_replayed_receipt(target: &std::path::Path, run_id: &str) {
    let read = read_run_items(target, run_id).unwrap().unwrap();
    assert_eq!(read.health, ProjectionHealth::Healthy);
    assert!(read.items.iter().any(|envelope| match &envelope.item {
        RunItemV1::ModelCallFinished {
            usage,
            cost,
            status,
            ..
        } => {
            assert_eq!(usage.input_tokens, Some(19));
            assert_eq!(usage.output_tokens, Some(7));
            assert_eq!(cost.observed_usd(), 0.75);
            assert_eq!(*status, RunItemStatus::Completed);
            true
        }
        _ => false,
    }));
    let projection = crate::run_lifecycle::load_run_projection(target, run_id)
        .unwrap()
        .projection;
    assert_eq!(projection.observed_model_cost.observed_usd(), 0.75);
    assert_eq!(projection.terminal.unwrap().status, RunItemStatus::Partial);
}
