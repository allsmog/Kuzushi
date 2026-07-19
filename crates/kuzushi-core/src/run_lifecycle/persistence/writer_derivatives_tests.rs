use super::*;
use crate::run_lifecycle::{
    CommittedItemSubscriber, CommittedRangeSubscriber, DiagnosticLevel, RunItemId, RunItemRecord,
    RunItemSource, RunItemV1, SafeText,
};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::mpsc::SyncSender;
use std::sync::{mpsc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[test]
fn blocked_derivative_does_not_delay_later_canonical_delivery() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("blocked-derivative");
    persist_two_items(target.path(), &run_id);
    let harness = BlockedPumpHarness::start(target.path(), run_id);
    harness.publish(1);
    harness.entered.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(harness.items.recv_timeout(Duration::from_secs(2)).unwrap(), 1);
    assert_eq!(
        harness
            .ranges
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .through_seq,
        1
    );
    harness.publish(2);
    assert_eq!(harness.items.recv_timeout(Duration::from_secs(2)).unwrap(), 2);
    assert_eq!(
        harness
            .ranges
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .through_seq,
        2
    );
    harness.finish();
}

#[test]
fn derivative_retry_projects_every_sequence_once_after_post_read_fault() {
    let target = tempfile::tempdir().unwrap();
    let run_id = crate::run_artifacts::new_run_id("derivative-cursor-rollback");
    persist_two_items(target.path(), &run_id);
    let path = crate::run_artifacts::run_dir(target.path(), &run_id).join("items.jsonl");
    let displaced = path.with_extension("original");
    let cursor = replacement_fault_cursor(target.path(), &run_id, &path, &displaced);
    let projected = Arc::new(Mutex::new(Vec::new()));
    let mut pump = DerivativePump {
        target: target.path().to_path_buf(),
        run_id,
        latest_seq: Arc::new(AtomicU64::new(2)),
        subscriber: None,
        fault_subscriber: None,
        projector: recording_projector(&projected),
        cursor,
        pending: None,
    };

    assert_eq!(pump.attempt(0), 0);
    assert!(projected.lock().unwrap().is_empty());
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&displaced, &path).unwrap();

    assert_eq!(pump.attempt(0), 2);
    assert_eq!(*projected.lock().unwrap(), [1, 2]);
}

fn replacement_fault_cursor(
    target: &Path,
    run_id: &str,
    path: &Path,
    displaced: &Path,
) -> DeliveryCursor {
    let swapped = Arc::new(AtomicBool::new(false));
    let hook_swapped = Arc::clone(&swapped);
    let hook_path = path.to_path_buf();
    let hook_displaced = displaced.to_path_buf();
    let mut cursor = DeliveryCursor::open(target, run_id, 0).unwrap();
    cursor.set_post_read_hook(Arc::new(move || {
        if !hook_swapped.swap(true, Ordering::SeqCst) {
            std::fs::rename(&hook_path, &hook_displaced).unwrap();
            std::fs::copy(&hook_displaced, &hook_path).unwrap();
        }
    }));
    cursor
}

fn recording_projector(projected: &Arc<Mutex<Vec<u64>>>) -> DerivativeProjector {
    let output = Arc::clone(projected);
    Arc::new(move |_, _, items, _| {
        output
            .lock()
            .unwrap()
            .extend(items.iter().map(|item| item.seq));
        Vec::new()
    })
}

struct BlockedPumpHarness {
    latest_seq: Arc<AtomicU64>,
    item_wake: SyncSender<()>,
    range_wake: SyncSender<()>,
    derivative_wake: SyncSender<()>,
    item_thread: JoinHandle<()>,
    range_thread: JoinHandle<()>,
    derivative_thread: JoinHandle<()>,
    items: mpsc::Receiver<u64>,
    ranges: mpsc::Receiver<CommittedRange>,
    entered: mpsc::Receiver<()>,
    gate: Arc<(Mutex<bool>, Condvar)>,
}

impl BlockedPumpHarness {
    fn start(target: &Path, run_id: String) -> Self {
        let latest_seq = Arc::new(AtomicU64::new(0));
        let (canonical, items, ranges) = start_canonical_pumps(target, &run_id, &latest_seq);
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_sender, entered) = mpsc::channel();
        let projector = blocking_projector(Arc::clone(&gate), entered_sender);
        let (derivative_wake, derivative_thread) = start_derivative_delivery_pump_with(
            target.to_path_buf(),
            run_id,
            0,
            Arc::clone(&latest_seq),
            None,
            None,
            projector,
        )
        .unwrap();
        Self {
            latest_seq,
            item_wake: canonical.item_wake,
            range_wake: canonical.range_wake,
            derivative_wake,
            item_thread: canonical.item_thread,
            range_thread: canonical.range_thread,
            derivative_thread,
            items,
            ranges,
            entered,
            gate,
        }
    }

    fn publish(&self, through_seq: u64) {
        self.latest_seq.store(through_seq, Ordering::Release);
        self.item_wake.send(()).unwrap();
        self.range_wake.send(()).unwrap();
        self.derivative_wake.send(()).unwrap();
    }

    fn finish(self) {
        release_gate(&self.gate);
        drop(self.item_wake);
        drop(self.range_wake);
        drop(self.derivative_wake);
        self.item_thread.join().unwrap();
        self.range_thread.join().unwrap();
        self.derivative_thread.join().unwrap();
    }
}

struct CanonicalPumps {
    item_wake: SyncSender<()>,
    range_wake: SyncSender<()>,
    item_thread: JoinHandle<()>,
    range_thread: JoinHandle<()>,
}

impl CanonicalPumps {
    fn new(
        item: (SyncSender<()>, JoinHandle<()>),
        range: (Option<SyncSender<()>>, Option<JoinHandle<()>>),
    ) -> Self {
        Self {
            item_wake: item.0,
            item_thread: item.1,
            range_wake: range.0.unwrap(),
            range_thread: range.1.unwrap(),
        }
    }
}

fn start_canonical_pumps(
    target: &Path,
    run_id: &str,
    latest_seq: &Arc<AtomicU64>,
) -> (
    CanonicalPumps,
    mpsc::Receiver<u64>,
    mpsc::Receiver<CommittedRange>,
) {
    let (item_sender, items) = mpsc::channel();
    let item_subscriber: CommittedItemSubscriber =
        Arc::new(move |item| item_sender.send(item.seq).unwrap());
    let (range_sender, ranges) = mpsc::channel();
    let range_subscriber: CommittedRangeSubscriber =
        Arc::new(move |range| range_sender.send(range).unwrap());
    let item = super::super::writer_delivery::start_item_delivery_pump(
        target.to_path_buf(),
        run_id.to_string(),
        0,
        Arc::clone(latest_seq),
        Some(item_subscriber),
        None,
    )
    .unwrap();
    let range = super::super::writer_range_delivery::start_range_delivery_pump(
        0,
        Arc::clone(latest_seq),
        Some(range_subscriber),
        None,
    )
    .unwrap();
    (CanonicalPumps::new(item, range), items, ranges)
}

fn persist_two_items(target: &Path, run_id: &str) {
    let writer = super::super::RunItemWriter::open(target, run_id, None).unwrap();
    writer.emit_and_flush(diagnostic("one")).unwrap();
    writer.emit_and_flush(diagnostic("two")).unwrap();
    writer.shutdown().unwrap();
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

fn blocking_projector(
    gate: Arc<(Mutex<bool>, Condvar)>,
    entered_sender: mpsc::Sender<()>,
) -> DerivativeProjector {
    Arc::new(move |_, _, _, _| {
        let _ = entered_sender.send(());
        let (lock, changed) = &*gate;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = changed.wait(released).unwrap();
        }
        Vec::new()
    })
}

fn release_gate(gate: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, changed) = &**gate;
    *lock.lock().unwrap() = true;
    changed.notify_all();
}
