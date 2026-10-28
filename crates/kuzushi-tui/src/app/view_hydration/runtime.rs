use super::reader::FsViewArtifactReader;
use super::*;
use std::collections::BTreeSet;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;

mod worker;
use worker::spawn_hydration_worker;

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
    cancellation: ViewHydrationCancellation,
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
        let cancellation = ViewHydrationCancellation::default();
        for key in keys {
            match caught_read(self.reader.as_ref(), &target, &key, &cancellation) {
                Ok(Some(value)) => drain.results.push(ViewHydrationResult {
                    target: target.clone(),
                    key,
                    value,
                }),
                Ok(None) | Err(()) => drain.failures.push(ViewHydrationFailure {
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
        for batch in &self.handles {
            batch.cancellation.cancel();
        }
        self.in_flight.clear();
        self.retryable_failures.clear();
    }

    pub(crate) fn cancel_single_read(&mut self, key: &ViewHydrationKey) {
        for batch in &self.handles {
            if batch.keys.as_slice() == std::slice::from_ref(key) {
                batch.cancellation.cancel();
            }
        }
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
        let cancellation = ViewHydrationCancellation::default();
        let handle = spawn_hydration_worker(
            generation,
            target.clone(),
            keys.clone(),
            Arc::clone(&self.reader),
            cancellation.clone(),
            self.tx.clone(),
            wake,
        );
        self.handles.push(ViewHydrationBatch {
            generation,
            target,
            keys,
            cancellation,
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
                    cancellation,
                    handle,
                } = batch;
                let panicked = handle.join().is_err();
                release_canceled_batch_claims(
                    batch_generation,
                    &keys,
                    &cancellation,
                    self.generation,
                    &mut self.in_flight,
                );
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

fn release_canceled_batch_claims(
    generation: u64,
    keys: &[ViewHydrationKey],
    cancellation: &ViewHydrationCancellation,
    current_generation: u64,
    in_flight: &mut BTreeSet<ViewHydrationKey>,
) {
    if generation != current_generation || !cancellation.is_canceled() {
        return;
    }
    for key in keys {
        in_flight.remove(key);
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[test]
    fn canceled_claims_are_released_without_erasing_a_newer_generation() {
        let key = ViewHydrationKey::TargetBase;
        let cancellation = ViewHydrationCancellation::default();
        cancellation.cancel();
        let mut claims = BTreeSet::from([key.clone()]);
        release_canceled_batch_claims(1, std::slice::from_ref(&key), &cancellation, 2, &mut claims);
        assert!(claims.contains(&key));
        release_canceled_batch_claims(2, std::slice::from_ref(&key), &cancellation, 2, &mut claims);
        assert!(claims.is_empty());
    }
}

fn caught_read(
    reader: &dyn ViewArtifactReader,
    target: &Path,
    key: &ViewHydrationKey,
    cancellation: &ViewHydrationCancellation,
) -> Result<Option<ViewHydrationValue>, ()> {
    kuzushi_core::recovered_panic::catch(|| reader.read_cancellable(target, key, cancellation))
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
