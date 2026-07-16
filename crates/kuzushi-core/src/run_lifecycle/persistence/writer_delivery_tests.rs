use super::*;
use crate::run_lifecycle::{
    DiagnosticLevel, OperationFingerprint, RunCallId, RunItemId, RunItemRecord, RunItemSource,
    RunItemV1, SafeText,
};
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn item_subscriber_panic_reports_delivery_fault_without_failing_durability() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("item-subscriber-panic");
    let (fault_sender, fault_receiver) = mpsc::channel();
    let subscriber: CommittedItemSubscriber = Arc::new(|_| panic!("subscriber failed"));
    let fault_subscriber: RunItemDeliveryFaultSubscriber =
        Arc::new(move |fault| fault_sender.send(fault).unwrap());
    let writer = super::super::RunItemWriter::open_with_delivery_subscribers(
        target.path(),
        &run_id,
        Some(subscriber),
        None,
        Some(fault_subscriber),
    )
    .unwrap();

    let committed = writer.emit_and_flush(diagnostic("committed")).unwrap();
    let fault = fault_receiver.recv_timeout(Duration::from_secs(2)).unwrap();

    assert_eq!(fault.stage, RunItemDeliveryFailureStage::ItemSubscriber);
    assert_eq!(fault.applied_seq, 0);
    assert_eq!(fault.durable_seq, committed.seq);
    writer.shutdown().unwrap();
    let read = read_run_items(target.path(), &run_id).unwrap().unwrap();
    assert_eq!(read.health, ProjectionHealth::Healthy);
    assert_eq!(read.items.last().map(|item| item.seq), Some(committed.seq));
}

#[test]
fn range_subscriber_panic_reports_delivery_fault_without_retracting_commit() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("range-subscriber-panic");
    let (fault_sender, fault_receiver) = mpsc::channel();
    let range_subscriber: CommittedRangeSubscriber = Arc::new(|_| panic!("range failed"));
    let fault_subscriber: RunItemDeliveryFaultSubscriber =
        Arc::new(move |fault| fault_sender.send(fault).unwrap());
    let writer = super::super::RunItemWriter::open_with_delivery_subscribers(
        target.path(),
        &run_id,
        None,
        Some(range_subscriber),
        Some(fault_subscriber),
    )
    .unwrap();

    let committed = writer.emit_and_flush(diagnostic("committed")).unwrap();
    let fault = fault_receiver.recv_timeout(Duration::from_secs(2)).unwrap();

    assert_eq!(fault.stage, RunItemDeliveryFailureStage::RangeSubscriber);
    assert_eq!(fault.applied_seq, 0);
    assert_eq!(fault.durable_seq, committed.seq);
    writer.shutdown().unwrap();
}

#[test]
fn missing_and_empty_streams_are_structured_delivery_faults() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("missing-delivery-stream");
    let missing = delivery_batch(target.path(), &run_id, 0, 1).unwrap_err();
    assert_eq!(missing.stage, RunItemDeliveryFailureStage::ReadStream);

    let path = crate::run_artifacts::run_dir(target.path(), &run_id).join("items.jsonl");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::File::create(path).unwrap();
    let empty = delivery_batch(target.path(), &run_id, 0, 1).unwrap_err();
    assert_eq!(empty.stage, RunItemDeliveryFailureStage::EmptyBatch);
    assert_eq!(empty.applied_seq, 0);
    assert_eq!(empty.durable_seq, 1);
}

#[test]
fn derivative_failure_is_reported_without_blocking_canonical_item_delivery() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("derivative-failure");
    let (item_sender, item_receiver) = mpsc::channel();
    let (fault_sender, fault_receiver) = mpsc::channel();
    let item_subscriber: CommittedItemSubscriber =
        Arc::new(move |item| item_sender.send(item.seq).unwrap());
    let fault_subscriber: RunItemDeliveryFaultSubscriber =
        Arc::new(move |fault| fault_sender.send(fault).unwrap());
    let writer = super::super::RunItemWriter::open_with_delivery_subscribers(
        target.path(),
        &run_id,
        Some(item_subscriber),
        None,
        Some(fault_subscriber),
    )
    .unwrap();
    let events_path = crate::run_artifacts::run_dir(target.path(), &run_id).join("events.jsonl");
    std::fs::create_dir(&events_path).unwrap();

    let committed = writer.emit_and_flush(requested_call()).unwrap();
    let fault = fault_receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    let delivered_seq = item_receiver.recv_timeout(Duration::from_secs(2)).unwrap();

    assert_eq!(
        fault.stage,
        RunItemDeliveryFailureStage::CompatibilityProjection
    );
    assert_eq!(fault.durable_seq, committed.seq);
    assert_eq!(delivered_seq, committed.seq);
    writer.shutdown().unwrap();
    let read = read_run_items(target.path(), &run_id).unwrap().unwrap();
    assert_eq!(read.health, ProjectionHealth::Healthy);
}

#[test]
fn derivative_pump_replays_the_initial_durable_backlog() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("derivative-backlog");
    let (initial_sender, initial_receiver) = mpsc::channel();
    let initial_subscriber: DerivativeRangeSubscriber =
        Arc::new(move |range| initial_sender.send(range).unwrap());
    let writer = super::super::RunItemWriter::open_with_derivative_delivery_subscriber(
        target.path(),
        &run_id,
        None,
        None,
        Some(initial_subscriber),
        None,
    )
    .unwrap();
    let committed = writer.emit_and_flush(requested_call()).unwrap();
    initial_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    writer.shutdown().unwrap();
    let events_path = crate::run_artifacts::run_dir(target.path(), &run_id).join("events.jsonl");
    std::fs::remove_file(&events_path).unwrap();
    let (derivative_sender, derivative_receiver) = mpsc::channel();
    let derivative_subscriber: DerivativeRangeSubscriber =
        Arc::new(move |range| derivative_sender.send(range).unwrap());
    let reopened = super::super::RunItemWriter::open_with_derivative_delivery_subscriber(
        target.path(),
        &run_id,
        None,
        None,
        Some(derivative_subscriber),
        None,
    )
    .unwrap();

    let range = derivative_receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    reopened.shutdown().unwrap();
    assert_eq!(range.through_seq, committed.seq);
    assert!(std::fs::read_to_string(events_path)
        .unwrap()
        .contains(&format!("[typed:{}]", committed.event_hash)));
}

#[test]
fn derivative_fault_retries_from_its_last_applied_sequence() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("derivative-retry");
    let events_path = crate::run_artifacts::run_dir(target.path(), &run_id).join("events.jsonl");
    let channels = derivative_retry_channels();
    let writer = super::super::RunItemWriter::open_with_derivative_delivery_subscriber(
        target.path(),
        &run_id,
        Some(channels.item_subscriber),
        None,
        Some(channels.derivative_subscriber),
        Some(channels.fault_subscriber),
    )
    .unwrap();
    std::fs::create_dir(&events_path).unwrap();
    let first = writer.emit_and_flush(requested_call()).unwrap();
    let fault = channels.faults.recv_timeout(Duration::from_secs(2)).unwrap();
    std::fs::remove_dir(&events_path).unwrap();
    let second = writer.emit_and_flush(requested_call()).unwrap();
    let applied = channels.derivatives.recv_timeout(Duration::from_secs(2)).unwrap();
    let delivered = [
        channels.items.recv_timeout(Duration::from_secs(2)).unwrap(),
        channels.items.recv_timeout(Duration::from_secs(2)).unwrap(),
    ];
    writer.shutdown().unwrap();

    assert!(fault.is_derivative());
    assert_eq!(fault.applied_seq, 0);
    assert_eq!(applied.first_seq, 1);
    assert_eq!(applied.through_seq, second.seq);
    assert_eq!(delivered, [first.seq, second.seq]);
}

#[test]
fn compatibility_derivative_redelivery_is_idempotent() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("derivative-idempotency");
    let writer = super::super::RunItemWriter::open(target.path(), &run_id, None).unwrap();
    writer.emit_and_flush(requested_call()).unwrap();
    writer.shutdown().unwrap();
    let read = read_run_items(target.path(), &run_id).unwrap().unwrap();

    assert!(
        super::super::writer_derivatives::deliver_committed_derivatives(
            target.path(),
            &run_id,
            &read.items,
            0,
        )
            .is_empty()
    );
    assert!(
        super::super::writer_derivatives::deliver_committed_derivatives(
            target.path(),
            &run_id,
            &read.items,
            0,
        )
            .is_empty()
    );
    let marker = format!("[typed:{}]", read.items[0].event_hash);
    let events = crate::run_artifacts::load_run_events(target.path(), &run_id).unwrap();
    assert_eq!(
        events
            .events
            .iter()
            .filter(|event| event.message.contains(&marker))
            .count(),
        1
    );
}

fn diagnostic(message: &str) -> RunItemRecord {
    RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Persistence,
        RunItemV1::DiagnosticNotice {
            level: DiagnosticLevel::Info,
            message: SafeText::operator_visible(message),
        },
    )
}

fn requested_call() -> RunItemRecord {
    RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Dispatch,
        RunItemV1::ToolCallRequested {
            tool_name: SafeText::operator_visible("security:scan"),
            operation_fingerprint: OperationFingerprint::from_bytes(b"derivative-test"),
            safe_option_names: Vec::new(),
        },
    )
    .with_call(RunCallId::new())
}

struct DerivativeRetryChannels {
    item_subscriber: CommittedItemSubscriber,
    derivative_subscriber: DerivativeRangeSubscriber,
    fault_subscriber: RunItemDeliveryFaultSubscriber,
    items: mpsc::Receiver<u64>,
    derivatives: mpsc::Receiver<CommittedRange>,
    faults: mpsc::Receiver<RunItemDeliveryFault>,
}

fn derivative_retry_channels() -> DerivativeRetryChannels {
    let (item_sender, items) = mpsc::channel();
    let (derivative_sender, derivatives) = mpsc::channel();
    let (fault_sender, faults) = mpsc::channel();
    DerivativeRetryChannels {
        item_subscriber: Arc::new(move |item| item_sender.send(item.seq).unwrap()),
        derivative_subscriber: Arc::new(move |range| derivative_sender.send(range).unwrap()),
        fault_subscriber: Arc::new(move |fault| fault_sender.send(fault).unwrap()),
        items,
        derivatives,
        faults,
    }
}
