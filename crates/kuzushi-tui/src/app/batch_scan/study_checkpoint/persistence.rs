use super::*;

impl StudyCheckpointRuntime {
    pub(crate) fn configure(&mut self, root: PathBuf, session_id: String) {
        self.binding = Some((EditorCheckpointStore::for_study_drafts(root), session_id));
    }

    pub(super) fn enqueue(&mut self, mut record: StudyCheckpointRecord) -> anyhow::Result<()> {
        record.validate()?;
        let id = record.record_id.clone();
        record.saved_at_seconds = self
            .states
            .get(&id)
            .map_or(0, |s| s.record.saved_at_seconds);
        if self
            .states
            .get(&id)
            .is_some_and(|s| s.record == record && !matches!(s.status, WriteStatus::Failed(_)))
        {
            return Ok(());
        }
        self.check_capacity(&id, &record)?;
        let generation = self.states.get(&id).map_or(1, |s| s.generation + 1);
        record.saved_at_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        self.pending
            .insert(id.clone(), (generation, record.clone()));
        self.states.insert(
            id,
            StudyWriteState {
                generation,
                record,
                status: WriteStatus::Pending,
            },
        );
        self.start_next();
        Ok(())
    }

    fn check_capacity(&self, id: &str, record: &StudyCheckpointRecord) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.states.contains_key(id) || self.states.len() < 32,
            "Local study checkpoint limit reached; keep this session or prepare its plan"
        );
        let mut bytes = serde_json::to_vec(record)?.len();
        for (key, state) in &self.states {
            if key != id {
                bytes = bytes.saturating_add(serde_json::to_vec(&state.record)?.len());
            }
        }
        anyhow::ensure!(
            bytes <= 32 * 1024 * 1024,
            "Local study checkpoint byte limit reached; choices remain in this session"
        );
        Ok(())
    }

    fn start_next(&mut self) {
        if self.active.is_some() {
            return;
        }
        let Some((id, (generation, record))) = self.pending.pop_first() else {
            return;
        };
        let store = self.binding.as_ref().unwrap().0.clone();
        let (send, receive) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("study-checkpoint".into())
            .spawn(move || {
                let _ = send.send(write_record(&store, record).map_err(|error| error.to_string()));
            });
        match spawned {
            Ok(_) => self.active = Some((id, generation, receive)),
            Err(error) => {
                self.states.get_mut(&id).unwrap().status = WriteStatus::Failed(error.to_string())
            }
        }
    }

    pub(super) fn drain_write(&mut self) -> bool {
        if self.active.is_none() && !self.pending.is_empty() {
            self.start_next();
            return true;
        }
        let Some(result) = self.take_result() else {
            return false;
        };
        let (id, generation, _) = self.active.take().unwrap();
        update_result(self.states.get_mut(&id), generation, result);
        self.start_next();
        true
    }

    fn take_result(&self) -> Option<Result<(), String>> {
        match self.active.as_ref()?.2.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => Some(Err(
                "Local study writer stopped; choices remain in this session".into(),
            )),
        }
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.active.is_some() || !self.pending.is_empty()
    }
}

fn update_result(state: Option<&mut StudyWriteState>, generation: u64, result: Result<(), String>) {
    if let Some(state) = state.filter(|s| s.generation == generation) {
        state.status = match result {
            Ok(()) => WriteStatus::Saved,
            Err(error) => WriteStatus::Failed(error),
        };
    }
}

fn write_record(
    store: &EditorCheckpointStore,
    mut next: StudyCheckpointRecord,
) -> anyhow::Result<()> {
    if let Some(previous) = store.read_record(&next.target, &next.record_id)? {
        let previous = decode(previous, &next.target)?;
        anyhow::ensure!(
            previous.record.session_id == next.session_id,
            "Study checkpoint owner changed; previous choices retained"
        );
        next.resolved_hashes = next
            .resolved_hashes
            .iter()
            .chain(&previous.record.resolved_hashes)
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
    next.validate()?;
    store.write(&next.target, &next.record_id, &serde_json::to_vec(&next)?)
}

pub(super) fn decode(
    file: EditorCheckpointFile,
    target: &std::path::Path,
) -> anyhow::Result<RecoveredStudyDraft> {
    let record: StudyCheckpointRecord = serde_json::from_slice(&file.bytes).map_err(|_| {
        anyhow::anyhow!("Saved study choices are malformed; original file retained")
    })?;
    record.validate()?;
    anyhow::ensure!(
        record.target == target && record.record_id == file.record_id,
        "Saved study checkpoint target or identity changed"
    );
    Ok(RecoveredStudyDraft {
        record,
        hash: file.sha256,
    })
}

pub(super) fn recover(
    store: &EditorCheckpointStore,
    target: &std::path::Path,
) -> anyhow::Result<Vec<RecoveredStudyDraft>> {
    let records: Vec<_> = store
        .read(target)?
        .into_iter()
        .map(|file| decode(file, target))
        .collect::<anyhow::Result<_>>()?;
    let resolved: BTreeSet<_> = records
        .iter()
        .flat_map(|r| r.record.resolved_hashes.iter().cloned())
        .collect();
    let mut records: Vec<_> = records
        .into_iter()
        .filter(|r| r.record.snapshot.is_some() && !resolved.contains(&r.hash))
        .collect();
    records.sort_by(|a, b| {
        (b.record.saved_at_seconds, &b.record.record_id)
            .cmp(&(a.record.saved_at_seconds, &a.record.record_id))
    });
    Ok(records)
}
