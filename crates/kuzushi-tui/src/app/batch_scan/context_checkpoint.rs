//! Bounded local checkpoint IO never occupies an agent or authorizes work.
use kuzushi_core::session_transcript::{
    ContextDraftRecord, ContextDraftStore, RecoveredContextDraft,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
mod application;
mod projection;
mod recovery;

type DraftKey = (PathBuf, String);
const MAX_PENDING_DRAFTS: usize = 32;
const MAX_PENDING_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Default)]
pub(crate) struct ContextCheckpointRuntime {
    binding: Option<(ContextDraftStore, String)>,
    states: BTreeMap<DraftKey, CheckpointState>,
    pending: BTreeMap<DraftKey, (u64, ContextDraftRecord)>,
    active: Option<(DraftKey, u64, Receiver<Result<(), String>>)>,
    recovery: Option<Receiver<recovery::RecoveryResult>>,
    recovery_request: Option<(DraftKey, kuzushi_core::ThreatModelRef)>,
}

#[derive(Debug)]
struct CheckpointState {
    generation: u64,
    record: ContextDraftRecord,
    status: CheckpointStatus,
}

#[derive(Debug)]
enum CheckpointStatus {
    Pending,
    Saved,
    Failed(String),
}

impl ContextCheckpointRuntime {
    pub(crate) fn configure(&mut self, root: PathBuf, session_id: String) {
        self.binding = Some((ContextDraftStore::from_sessions_root(root), session_id));
    }

    fn enqueue(&mut self, mut record: ContextDraftRecord) -> anyhow::Result<()> {
        let key = record_key(&record);
        record.saved_at_seconds = self
            .states
            .get(&key)
            .map_or(0, |s| s.record.saved_at_seconds);
        if self
            .states
            .get(&key)
            .is_some_and(|s| s.record == record && !matches!(s.status, CheckpointStatus::Failed(_)))
        {
            return Ok(());
        }
        self.check_capacity(&key, &record)?;
        record.saved_at_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let generation = self.states.get(&key).map_or(1, |s| s.generation + 1);
        self.pending
            .insert(key.clone(), (generation, record.clone()));
        self.states.insert(
            key,
            CheckpointState {
                generation,
                record,
                status: CheckpointStatus::Pending,
            },
        );
        self.start_next();
        Ok(())
    }

    fn check_capacity(&self, key: &DraftKey, record: &ContextDraftRecord) -> anyhow::Result<()> {
        anyhow::ensure!(self.states.contains_key(key) || self.states.len() < MAX_PENDING_DRAFTS, "Local draft checkpoint limit reached; keep this edit in the session or save its context copy");
        let retained: usize = self
            .states
            .iter()
            .filter(|(k, _)| *k != key)
            .map(|(_, s)| estimated_bytes(&s.record))
            .sum();
        anyhow::ensure!(
            retained + estimated_bytes(record) <= MAX_PENDING_BYTES,
            "Local draft checkpoint byte limit reached; this edit remains in the session"
        );
        Ok(())
    }

    fn start_next(&mut self) {
        if self.active.is_some() {
            return;
        }
        let Some((key, (generation, record))) = self.pending.pop_first() else {
            return;
        };
        let store = self.binding.as_ref().unwrap().0.clone();
        let (send, receive) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("context-checkpoint".into())
            .spawn(move || {
                let _ = send.send(store.write(&record).map_err(|error| error.to_string()));
            });
        self.record_started(key, generation, receive, spawned);
    }

    fn record_started(
        &mut self,
        key: DraftKey,
        generation: u64,
        receive: Receiver<Result<(), String>>,
        spawned: std::io::Result<std::thread::JoinHandle<()>>,
    ) {
        match spawned {
            Ok(_) => self.active = Some((key, generation, receive)),
            Err(error) => {
                self.states.get_mut(&key).unwrap().status =
                    CheckpointStatus::Failed(error.to_string())
            }
        }
    }

    fn drain_write(&mut self) -> bool {
        let Some(result) = self.take_write_result() else {
            return false;
        };
        let (key, generation, _) = self.active.take().unwrap();
        self.apply_write_result(&key, generation, result);
        self.start_next();
        true
    }

    fn take_write_result(&self) -> Option<Result<(), String>> {
        let receive = &self.active.as_ref()?.2;
        match receive.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err("Local checkpoint worker stopped".into()))
            }
        }
    }

    fn apply_write_result(&mut self, key: &DraftKey, generation: u64, result: Result<(), String>) {
        if let Some(state) = self
            .states
            .get_mut(key)
            .filter(|s| s.generation == generation)
        {
            state.status = match result {
                Ok(()) => CheckpointStatus::Saved,
                Err(error) => CheckpointStatus::Failed(error),
            };
        }
    }

    pub(crate) fn has_pending_writes(&self) -> bool {
        self.active.is_some() || !self.pending.is_empty()
    }
}

fn record_key(record: &ContextDraftRecord) -> DraftKey {
    (
        record.target.clone(),
        record.source.revision_id.as_str().into(),
    )
}

fn estimated_bytes(record: &ContextDraftRecord) -> usize {
    record.snapshot.as_ref().map_or(8192, |s| {
        8192 + 6 * s.name.text.len()
            + s.fields
                .iter()
                .map(|f| 128 + 6 * (f.pointer.len() + f.text.as_ref().map_or(0, String::len)))
                .sum::<usize>()
    })
}
