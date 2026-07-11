use super::reader::FsViewArtifactReader;
use super::*;
use std::collections::BTreeSet;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;

const VIEW_HYDRATION_CHANNEL_CAPACITY: usize = 128;
pub(super) const MAX_VIEW_HYDRATION_WORKERS: usize = 2;

#[derive(Debug)]
enum ViewHydrationMessage {
    Result {
        generation: u64,
        result: ViewHydrationResult,
    },
    Failed {
        generation: u64,
        target: PathBuf,
        key: ViewHydrationKey,
    },
}

#[derive(Debug)]
struct ViewHydrationBatch {
    generation: u64,
    target: PathBuf,
    keys: Vec<ViewHydrationKey>,
    handle: JoinHandle<()>,
}

#[derive(Debug)]
pub(crate) struct ViewHydrationRuntime {
    generation: u64,
    active_target: Option<PathBuf>,
    in_flight: BTreeSet<ViewHydrationKey>,
    tx: SyncSender<ViewHydrationMessage>,
    rx: Receiver<ViewHydrationMessage>,
    handles: Vec<ViewHydrationBatch>,
    retryable_failures: Vec<ViewHydrationFailure>,
    reader: Arc<dyn ViewArtifactReader>,
}

impl Default for ViewHydrationRuntime {
    fn default() -> Self {
        let (tx, rx) = mpsc::sync_channel(VIEW_HYDRATION_CHANNEL_CAPACITY);
        Self {
            generation: 0,
            active_target: None,
            in_flight: BTreeSet::new(),
            tx,
            rx,
            handles: Vec::new(),
            retryable_failures: Vec::new(),
            reader: Arc::new(FsViewArtifactReader),
        }
    }
}

impl ViewHydrationRuntime {
    pub(crate) fn schedule(
        &mut self,
        target: PathBuf,
        keys: Vec<ViewHydrationKey>,
        wake: Option<TerminalLoopWake>,
    ) -> Vec<ViewHydrationKey> {
        self.activate_target(&target);
        self.reap_finished();
        if self.handles.len() >= MAX_VIEW_HYDRATION_WORKERS {
            return Vec::new();
        }
        let pending = self.claim_pending_keys(keys);
        if pending.is_empty() {
            return pending;
        }
        self.spawn_batch(target, pending.clone(), wake);
        pending
    }

    pub(crate) fn hydrate_blocking(
        &mut self,
        target: PathBuf,
        keys: Vec<ViewHydrationKey>,
    ) -> ViewHydrationDrain {
        self.activate_target(&target);
        let mut drain = ViewHydrationDrain::default();
        for key in keys {
            match caught_read(self.reader.as_ref(), &target, &key) {
                Ok(value) => drain.results.push(ViewHydrationResult {
                    target: target.clone(),
                    key,
                    value,
                }),
                Err(()) => drain.failures.push(ViewHydrationFailure {
                    target: target.clone(),
                    key,
                }),
            }
        }
        drain
    }

    pub(crate) fn drain_current(&mut self) -> ViewHydrationDrain {
        let mut drain = ViewHydrationDrain::default();
        while let Ok(message) = self.rx.try_recv() {
            self.apply_message(message, &mut drain);
        }
        self.reap_finished();
        drain.failures.append(&mut self.retryable_failures);
        drain
    }

    pub(crate) fn invalidate(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.in_flight.clear();
        self.retryable_failures.clear();
    }

    #[cfg(test)]
    pub(crate) fn set_reader(&mut self, reader: Arc<dyn ViewArtifactReader>) {
        self.invalidate();
        self.reader = reader;
    }

    #[cfg(test)]
    pub(super) fn workers_finished(&self) -> bool {
        self.handles.iter().all(|batch| batch.handle.is_finished())
    }

    #[cfg(test)]
    pub(super) fn worker_count(&self) -> usize {
        self.handles.len()
    }

    fn claim_pending_keys(&mut self, keys: Vec<ViewHydrationKey>) -> Vec<ViewHydrationKey> {
        keys.into_iter()
            .filter(|key| self.in_flight.insert(key.clone()))
            .collect()
    }

    fn spawn_batch(
        &mut self,
        target: PathBuf,
        keys: Vec<ViewHydrationKey>,
        wake: Option<TerminalLoopWake>,
    ) {
        let generation = self.generation;
        let handle = spawn_hydration_worker(
            generation,
            target.clone(),
            keys.clone(),
            Arc::clone(&self.reader),
            self.tx.clone(),
            wake,
        );
        self.handles.push(ViewHydrationBatch {
            generation,
            target,
            keys,
            handle,
        });
    }

    fn apply_message(&mut self, message: ViewHydrationMessage, drain: &mut ViewHydrationDrain) {
        match message {
            ViewHydrationMessage::Result { generation, result }
                if self.is_current(generation, &result.target) =>
            {
                self.in_flight.remove(&result.key);
                drain.results.push(result);
            }
            ViewHydrationMessage::Failed {
                generation,
                target,
                key,
            } if self.is_current(generation, &target) => {
                self.in_flight.remove(&key);
                drain.failures.push(ViewHydrationFailure { target, key });
            }
            _ => {}
        }
    }

    fn activate_target(&mut self, target: &Path) {
        if self.active_target.as_deref() == Some(target) {
            return;
        }
        self.active_target = Some(target.to_path_buf());
        self.invalidate();
    }

    fn is_current(&self, generation: u64, target: &Path) -> bool {
        generation == self.generation && self.active_target.as_deref() == Some(target)
    }

    fn reap_finished(&mut self) {
        let mut active = Vec::with_capacity(self.handles.len());
        for batch in self.handles.drain(..) {
            if batch.handle.is_finished() {
                let ViewHydrationBatch {
                    generation: batch_generation,
                    target,
                    keys,
                    handle,
                } = batch;
                let panicked = handle.join().is_err();
                collect_panicked_batch_failures(
                    batch_generation,
                    target,
                    keys,
                    panicked,
                    self.generation,
                    self.active_target.as_deref(),
                    &mut self.in_flight,
                    &mut self.retryable_failures,
                );
            } else {
                active.push(batch);
            }
        }
        self.handles = active;
    }
}

fn spawn_hydration_worker(
    generation: u64,
    target: PathBuf,
    keys: Vec<ViewHydrationKey>,
    reader: Arc<dyn ViewArtifactReader>,
    tx: SyncSender<ViewHydrationMessage>,
    wake: Option<TerminalLoopWake>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        for key in keys {
            let message = hydration_message(generation, &target, key, reader.as_ref());
            if tx.send(message).is_err() {
                return;
            }
            if let Some(wake) = wake.as_ref() {
                wake.notify();
            }
        }
    })
}

fn hydration_message(
    generation: u64,
    target: &Path,
    key: ViewHydrationKey,
    reader: &dyn ViewArtifactReader,
) -> ViewHydrationMessage {
    match caught_read(reader, target, &key) {
        Ok(value) => ViewHydrationMessage::Result {
            generation,
            result: ViewHydrationResult {
                target: target.to_path_buf(),
                key,
                value,
            },
        },
        Err(()) => ViewHydrationMessage::Failed {
            generation,
            target: target.to_path_buf(),
            key,
        },
    }
}

fn caught_read(
    reader: &dyn ViewArtifactReader,
    target: &Path,
    key: &ViewHydrationKey,
) -> Result<ViewHydrationValue, ()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| reader.read(target, key)))
        .map_err(|_| ())
}

fn collect_panicked_batch_failures(
    batch_generation: u64,
    target: PathBuf,
    keys: Vec<ViewHydrationKey>,
    panicked: bool,
    generation: u64,
    active_target: Option<&Path>,
    in_flight: &mut BTreeSet<ViewHydrationKey>,
    failures: &mut Vec<ViewHydrationFailure>,
) {
    if !panicked || batch_generation != generation || active_target != Some(&target) {
        return;
    }
    for key in keys {
        if in_flight.remove(&key) {
            failures.push(ViewHydrationFailure {
                target: target.clone(),
                key,
            });
        }
    }
}
