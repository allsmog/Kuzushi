//! Source-index groups never include operator decisions or finding writes.
use super::*;
use crate::event_log::{EventAppend, MAX_APPEND_BATCH_EVENTS};

impl StorageWriterActor {
    pub(crate) fn commit_source_index(
        log_dir: PathBuf,
        projection_path: PathBuf,
        commands: Vec<WriterCommand>,
        committed: &mut dyn FnMut(usize),
        canceled: &dyn Fn() -> bool,
    ) -> Result<Vec<WriteReceipt>> {
        require_not_canceled(canceled)?;
        let writer = StorageWriter::open_cancellable(&log_dir, &projection_path, canceled)?;
        let mut session = StorageWriterSession { writer };
        session.commit_source_index(commands, committed, canceled)
    }
}

impl StorageWriterSession {
    fn commit_source_index(
        &mut self,
        commands: Vec<WriterCommand>,
        committed: &mut dyn FnMut(usize),
        canceled: &dyn Fn() -> bool,
    ) -> Result<Vec<WriteReceipt>> {
        for command in &commands {
            require_index_command(command)?;
        }
        let mut receipts = Vec::with_capacity(commands.len());
        for chunk in commands.chunks(MAX_APPEND_BATCH_EVENTS) {
            require_not_canceled(canceled)?;
            receipts.extend(self.writer.commit_index_chunk(chunk)?);
            committed(receipts.len());
        }
        require_not_canceled(canceled)?;
        Ok(receipts)
    }
}

impl StorageWriter {
    fn commit_index_chunk(&mut self, commands: &[WriterCommand]) -> Result<Vec<WriteReceipt>> {
        self.replay_projection()?;
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let records = commands
            .iter()
            .map(index_record)
            .collect::<Result<Vec<_>>>()?;
        let events = self.log.append_batch(records)?;
        for event in &events {
            #[cfg(test)]
            test_hooks::after_event_append(event);
            self.lifecycle.append_committed_event(event.seq)?;
        }
        let projections = match self.projection.apply_event_batch(&events) {
            Ok(receipts) => receipts,
            Err(error) => {
                self.lifecycle.projection_failed();
                return Err(error);
            }
        };
        self.lifecycle
            .projection_advanced(self.lifecycle.log_head())?;
        let generation = self.projection.meta()?.generation;
        Ok(events
            .iter()
            .zip(projections)
            .map(|(event, projection)| WriteReceipt {
                committed_seq: event.seq,
                event_hash: event.event_hash.as_str().into(),
                projection_generation: generation,
                projected_finding_id: projection.finding_id,
                projected_review_decision_id: projection.review_decision_id,
            })
            .collect())
    }
}

fn require_index_command(command: &WriterCommand) -> Result<()> {
    anyhow::ensure!(
        matches!(
            command,
            WriterCommand::Watcher(
                WatcherCommand::SnapshotIndexed(_)
                    | WatcherCommand::FileIndexed(_)
                    | WatcherCommand::FileDeleted(_)
            )
        ),
        "Source-index batches accept only snapshot, file and deletion events"
    );
    Ok(())
}

fn index_record(command: &WriterCommand) -> Result<EventAppend> {
    let (kind, actor, payload) = match command {
        WriterCommand::Watcher(WatcherCommand::SnapshotIndexed(value)) => (
            EventKind::SnapshotIndexed,
            value.actor.clone(),
            value.payload(),
        ),
        WriterCommand::Watcher(WatcherCommand::FileIndexed(value)) => {
            (EventKind::FileIndexed, value.actor.clone(), value.payload())
        }
        WriterCommand::Watcher(WatcherCommand::FileDeleted(value)) => {
            (EventKind::FileDeleted, value.actor.clone(), value.payload())
        }
        _ => anyhow::bail!("Source-index batches cannot contain decisions or findings"),
    };
    Ok(EventAppend {
        kind,
        actor,
        payload,
    })
}

fn require_not_canceled(canceled: &dyn Fn() -> bool) -> Result<()> {
    anyhow::ensure!(
        !canceled(),
        "Source-index persistence was canceled; committed batches remain available for recovery"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
