use super::records::{
    diagnostic, diagnostic_count, omitted_progress, progress, progress_count, terminal_record,
};
use crate::run_lifecycle::{
    read_run_items, CommittedItemSubscriber, ProjectionHealth, RunItemId, RunItemStatus,
    RunItemWriter,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread::JoinHandle;
use std::time::Duration;

pub(super) fn exercise_concurrent_producer_case(producer_count: usize) {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id(&format!("producers-{producer_count}"));
    let writer = RunItemWriter::open(target.path(), &run_id, Some(slow_subscriber())).unwrap();
    run_producers(&writer, producer_count);
    writer.flush().unwrap();
    writer.shutdown().unwrap();

    let durable_tail = assert_mixed_traffic(target.path(), &run_id);
    assert_reopen_at_durable_tail(target.path(), &run_id, durable_tail);
}

fn slow_subscriber() -> CommittedItemSubscriber {
    let first_delivery = Arc::new(AtomicBool::new(true));
    Arc::new(move |_| {
        if first_delivery.swap(false, Ordering::AcqRel) {
            std::thread::sleep(Duration::from_millis(100));
        }
    })
}

fn run_producers(writer: &RunItemWriter, producer_count: usize) {
    let barrier = Arc::new(Barrier::new(producer_count + 1));
    let progress_item_id = RunItemId::new();
    let producers = producer_threads(writer, &barrier, progress_item_id, producer_count);
    barrier.wait();
    for producer in producers {
        producer.join().unwrap();
    }
}

fn producer_threads(
    writer: &RunItemWriter,
    barrier: &Arc<Barrier>,
    progress_item_id: RunItemId,
    producer_count: usize,
) -> Vec<JoinHandle<()>> {
    (0..producer_count)
        .map(|producer| {
            let writer = writer.clone();
            let barrier = Arc::clone(barrier);
            std::thread::spawn(move || {
                barrier.wait();
                emit_producer_traffic(&writer, producer, producer_count, progress_item_id);
            })
        })
        .collect()
}

fn emit_producer_traffic(
    writer: &RunItemWriter,
    producer: usize,
    producer_count: usize,
    progress_item_id: RunItemId,
) {
    for operation in (producer..100).step_by(producer_count) {
        if operation < 10 {
            writer
                .emit(diagnostic(&format!("lossless-{operation}")))
                .unwrap();
        } else {
            writer
                .emit_coalescible(progress(progress_item_id, operation as u64))
                .unwrap();
        }
    }
}

fn assert_mixed_traffic(target: &std::path::Path, run_id: &str) -> u64 {
    let read = read_run_items(target, run_id).unwrap().unwrap();
    assert_eq!(read.health, ProjectionHealth::Healthy);
    assert_eq!(diagnostic_count(&read.items), 10);
    assert_eq!(
        progress_count(&read.items) + omitted_progress(&read.items),
        90
    );
    read.items.last().unwrap().seq
}

fn assert_reopen_at_durable_tail(target: &std::path::Path, run_id: &str, durable_tail: u64) {
    let reopened = RunItemWriter::open(target, run_id, None).unwrap();
    let appended = reopened.emit_and_flush(terminal_record()).unwrap();
    reopened.shutdown().unwrap();
    assert_eq!(appended.seq, durable_tail + 1);
    let projection = crate::run_lifecycle::load_run_projection(target, run_id)
        .unwrap()
        .projection;
    assert_eq!(projection.health, ProjectionHealth::Healthy);
    assert_eq!(
        projection.terminal.map(|terminal| terminal.status),
        Some(RunItemStatus::Completed)
    );
}
