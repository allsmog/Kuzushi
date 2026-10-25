use super::*;
use crate::run_lifecycle::{
    load_run_projection, read_run_items, DiagnosticLevel, ProjectionHealth, RunItemId,
    RunItemRecord, RunItemSource, RunItemV1, SafeText,
};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::time::Duration;

const DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);

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
    let fault = fault_receiver.recv_timeout(DELIVERY_TIMEOUT).unwrap();

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
    let fault = fault_receiver.recv_timeout(DELIVERY_TIMEOUT).unwrap();

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
fn delivery_cursor_reads_each_committed_record_once_across_batches() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("incremental-cursor");
    let writer = super::super::RunItemWriter::open(target.path(), &run_id, None).unwrap();
    let first = writer.emit_and_flush(diagnostic("first")).unwrap();
    let second = writer.emit_and_flush(diagnostic("second")).unwrap();
    let third = writer.emit_and_flush(diagnostic("third")).unwrap();
    writer.shutdown().unwrap();

    let mut cursor = DeliveryCursor::open(target.path(), &run_id, 0).unwrap();
    assert_eq!(cursor.read_through(first.seq).unwrap()[0].seq, first.seq);
    assert_eq!(cursor.read_through(second.seq).unwrap()[0].seq, second.seq);
    assert_eq!(cursor.read_through(third.seq).unwrap()[0].seq, third.seq);
    assert_eq!(cursor.records_read(), 3);
}

#[test]
fn delivery_cursor_faults_on_truncation_and_replacement() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("mutated-cursor");
    let writer = super::super::RunItemWriter::open(target.path(), &run_id, None).unwrap();
    let first = writer.emit_and_flush(diagnostic("first")).unwrap();
    let second = writer.emit_and_flush(diagnostic("second")).unwrap();
    writer.shutdown().unwrap();
    let path = crate::run_artifacts::run_dir(target.path(), &run_id).join("items.jsonl");

    let mut truncated = DeliveryCursor::open(target.path(), &run_id, 0).unwrap();
    truncated.read_through(first.seq).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(0)
        .unwrap();
    let fault = truncated.read_through(second.seq).unwrap_err();
    assert_eq!(fault.stage, RunItemDeliveryFailureStage::ReadStream);

    std::fs::remove_file(&path).unwrap();
    let writer = super::super::RunItemWriter::open(target.path(), &run_id, None).unwrap();
    let replacement_first = writer
        .emit_and_flush(diagnostic("replacement first"))
        .unwrap();
    let replacement_second = writer
        .emit_and_flush(diagnostic("replacement second"))
        .unwrap();
    writer.shutdown().unwrap();
    let mut replaced = DeliveryCursor::open(target.path(), &run_id, 0).unwrap();
    replaced.read_through(replacement_first.seq).unwrap();
    let replacement = path.with_extension("replacement");
    std::fs::copy(&path, &replacement).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    let fault = replaced.read_through(replacement_second.seq).unwrap_err();
    assert_eq!(fault.stage, RunItemDeliveryFailureStage::ReadStream);
    assert!(fault.detail.as_str().contains("replaced"));
}

#[test]
fn delivery_cursor_rolls_back_after_post_read_verification_failure() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("transactional-cursor");
    persist_diagnostics(target.path(), &run_id, ["first", "second"]);
    let path = crate::run_artifacts::run_dir(target.path(), &run_id).join("items.jsonl");
    let displaced = path.with_extension("original");
    let swapped = Arc::new(AtomicBool::new(false));
    let hook_swapped = Arc::clone(&swapped);
    let hook_path = path.clone();
    let hook_displaced = displaced.clone();
    let mut cursor = DeliveryCursor::open(target.path(), &run_id, 0).unwrap();
    cursor.set_post_read_hook(Arc::new(move || {
        if !hook_swapped.swap(true, Ordering::SeqCst) {
            std::fs::rename(&hook_path, &hook_displaced).unwrap();
            std::fs::copy(&hook_displaced, &hook_path).unwrap();
        }
    }));

    let fault = cursor.read_through(2).unwrap_err();
    assert!(fault.detail.as_str().contains("replaced"));
    assert_eq!(cursor.applied_seq(), 0);
    assert_eq!(cursor.records_read(), 0);

    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&displaced, &path).unwrap();
    let items = cursor.read_through(2).unwrap();
    assert_eq!(
        items.iter().map(|item| item.seq).collect::<Vec<_>>(),
        [1, 2]
    );
}

#[cfg(unix)]
#[test]
fn lifecycle_readers_reject_symlinked_run_parents() {
    use std::os::unix::fs::symlink;

    for symlink_run_directory in [false, true] {
        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let run_id = crate::run_artifacts::new_run_id("symlinked-parent");
        let runs = crate::run_artifacts::runs_root(target.path());
        std::fs::create_dir_all(runs.parent().unwrap()).unwrap();
        if symlink_run_directory {
            std::fs::create_dir(&runs).unwrap();
            symlink(outside.path(), runs.join(&run_id)).unwrap();
        } else {
            symlink(outside.path(), &runs).unwrap();
        }

        assert!(read_run_items(target.path(), &run_id).is_err());
        assert!(load_run_projection(target.path(), &run_id).is_err());
        assert!(DeliveryCursor::open(target.path(), &run_id, 0).is_err());
    }
}

fn persist_diagnostics<const N: usize>(target: &Path, run_id: &str, messages: [&str; N]) {
    let writer = super::super::RunItemWriter::open(target, run_id, None).unwrap();
    for message in messages {
        writer.emit_and_flush(diagnostic(message)).unwrap();
    }
    writer.shutdown().unwrap();
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
    let log_dir = poison_storage_log(target.path());

    let committed = writer.emit_and_flush(terminal_outcome()).unwrap();
    let fault = fault_receiver.recv_timeout(DELIVERY_TIMEOUT).unwrap();
    let delivered_seq = item_receiver.recv_timeout(DELIVERY_TIMEOUT).unwrap();

    assert_eq!(fault.stage, RunItemDeliveryFailureStage::StorageProjection);
    assert_eq!(fault.durable_seq, committed.seq);
    assert_eq!(delivered_seq, committed.seq);
    writer.shutdown().unwrap();
    let read = read_run_items(target.path(), &run_id).unwrap().unwrap();
    assert_eq!(read.health, ProjectionHealth::Healthy);
    std::fs::remove_file(log_dir).unwrap();
}

#[test]
fn derivative_pump_replays_the_initial_durable_backlog() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("derivative-backlog");
    let (initial_subscriber, initial_receiver) = derivative_range_channel();
    let writer = super::super::RunItemWriter::open_with_derivative_delivery_subscriber(
        target.path(),
        &run_id,
        None,
        None,
        Some(initial_subscriber),
        None,
    )
    .unwrap();
    let committed = writer.emit_and_flush(terminal_outcome()).unwrap();
    initial_receiver
        .recv_timeout(DELIVERY_TIMEOUT)
        .unwrap();
    writer.shutdown().unwrap();
    let (derivative_subscriber, derivative_receiver) = derivative_range_channel();
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
        .recv_timeout(DELIVERY_TIMEOUT)
        .unwrap();
    reopened.shutdown().unwrap();
    assert_eq!(range.through_seq, committed.seq);
    assert_eq!(
        storage_event_occurrences(target.path(), &committed.event_hash),
        1
    );
}

fn derivative_range_channel() -> (DerivativeRangeSubscriber, mpsc::Receiver<CommittedRange>) {
    let (sender, receiver) = mpsc::channel();
    let subscriber = Arc::new(move |range| sender.send(range).unwrap());
    (subscriber, receiver)
}

#[test]
fn derivative_fault_retries_from_its_last_applied_sequence() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("derivative-retry");
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
    let log_dir = poison_storage_log(target.path());
    let first = writer.emit_and_flush(terminal_outcome()).unwrap();
    let fault = channels
        .faults
        .recv_timeout(DELIVERY_TIMEOUT)
        .unwrap();
    std::fs::remove_file(&log_dir).unwrap();
    let second = writer
        .emit_and_flush(diagnostic("retry storage derivative"))
        .unwrap();
    let applied = channels
        .derivatives
        .recv_timeout(DELIVERY_TIMEOUT)
        .unwrap();
    let delivered = [
        channels.items.recv_timeout(DELIVERY_TIMEOUT).unwrap(),
        channels.items.recv_timeout(DELIVERY_TIMEOUT).unwrap(),
    ];
    writer.shutdown().unwrap();

    assert!(fault.is_derivative());
    assert_eq!(fault.applied_seq, 0);
    assert_eq!(applied.first_seq, 1);
    assert_eq!(applied.through_seq, second.seq);
    assert_eq!(delivered, [first.seq, second.seq]);
}

#[test]
fn terminal_storage_derivative_redelivery_is_idempotent() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("derivative-idempotency");
    let writer = super::super::RunItemWriter::open(target.path(), &run_id, None).unwrap();
    writer.emit_and_flush(terminal_outcome()).unwrap();
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
    assert_eq!(
        storage_event_occurrences(target.path(), &read.items[0].event_hash),
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

fn terminal_outcome() -> RunItemRecord {
    RunItemRecord::new(
        RunItemId::new(),
        RunItemSource::Persistence,
        RunItemV1::TerminalOutcome {
            status: crate::run_lifecycle::RunItemStatus::Completed,
            summary: SafeText::operator_visible("Run completed"),
            cost: crate::runtime::RuntimeCostReport::UNAVAILABLE,
            continuation: crate::run_lifecycle::WorkflowContinuation::NoFurtherAction {
                reason: SafeText::operator_visible("Run completed"),
            },
        },
    )
}

fn poison_storage_log(target: &std::path::Path) -> std::path::PathBuf {
    let workspace = crate::workspace::WorkspaceTarget::new(target).unwrap();
    let log_dir = workspace.event_log_dir();
    std::fs::create_dir_all(log_dir.parent().unwrap()).unwrap();
    std::fs::write(&log_dir, "not a directory").unwrap();
    log_dir
}

fn storage_event_occurrences(target: &std::path::Path, event_hash: &str) -> usize {
    let workspace = crate::workspace::WorkspaceTarget::new(target).unwrap();
    std::fs::read_dir(workspace.event_log_dir())
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .map(|body| body.matches(event_hash).count())
        .sum()
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
