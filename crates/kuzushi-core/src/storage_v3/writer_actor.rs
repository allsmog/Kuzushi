use super::ProjectionDb;
use crate::event_log::{EventEnvelope, EventKind, EventLog};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};

mod commands;
mod dispatch;
mod lifecycle;
mod lessons;
mod relationships;
mod staleness;
#[cfg(test)]
mod test_hooks;
mod writes;

pub use commands::{
    ControlCommand, DecisionCommand, WatcherCommand, WriteLane, WriterCommand, WriterLaneScheduler,
};
pub use commands::{StorageWriterActor, StorageWriterActorConfig, StorageWriterActorHandle};
use lifecycle::require_state;
pub use lifecycle::{WriterActorState, WriterLifecycle};
pub use writes::{
    AttackSurfaceWrite, AuditWrite, CandidateObservationWrite, DecisionWrite, FileDeletedWrite,
    FileFactWrite, FindingLifecycleWrite, ObservationWrite, PatchAttemptWrite, PatchLifecycleWrite,
    RekeyWrite, ReviewSessionWrite, RunLifecycleWrite, SnapshotWrite, SuppressionEventMeta,
    VerificationWrite,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteReceipt {
    pub committed_seq: u64,
    pub event_hash: String,
    pub projection_generation: u64,
    pub projected_finding_id: Option<i64>,
    pub projected_review_decision_id: Option<i64>,
}

struct StorageWriter {
    _ownership: crate::file_lock::ExclusiveFileLock,
    log: EventLog,
    projection: ProjectionDb,
    lifecycle: WriterLifecycle,
}

impl StorageWriter {
    fn open(log_dir: impl AsRef<Path>, projection_path: impl AsRef<Path>) -> Result<Self> {
        let (log_dir, projection_path) =
            normalize_storage_paths(log_dir.as_ref(), projection_path.as_ref())?;
        initialize_workspace_storage(&log_dir, &projection_path)?;
        let ownership =
            crate::file_lock::ExclusiveFileLock::acquire(&log_dir.join(".storage-writer.lock"))?;
        let log = EventLog::open(&log_dir)?;
        log.verify_chain()?;
        let projection = ProjectionDb::open(&projection_path)?;
        let mut lifecycle = WriterLifecycle::recovering();
        lifecycle.recover(log.head_seq()?, projection.meta()?.applied_seq)?;
        let mut writer = Self {
            _ownership: ownership,
            log,
            projection,
            lifecycle,
        };
        writer.replay_projection()?;
        Ok(writer)
    }

    fn record_review_decision(&mut self, mut decision: DecisionWrite) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        self.forward_or_reject_stale_decision(&mut decision)?;
        let event = self.log.append(
            decision.event_kind(),
            decision.author.clone(),
            None,
            None,
            decision.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    /// A session is an observation, not a verdict, so there is no staleness
    /// forwarding here: it records what the queue looked like, and a queue that
    /// moved afterwards does not make the observation wrong.
    fn record_review_session(&mut self, session: ReviewSessionWrite) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let event = self.log.append(
            EventKind::ReviewSessionStarted,
            session.actor.clone(),
            None,
            None,
            session.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    fn record_rekey(&mut self, rekey: RekeyWrite) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let event = self.log.append(
            EventKind::FindingRekeyed,
            rekey.actor.clone(),
            None,
            None,
            rekey.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    fn record_verification(&mut self, verification: VerificationWrite) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        if let Some(provenance) = &verification.provenance {
            provenance.validate()?;
        }
        let target_snapshot = verification
            .provenance
            .as_ref()
            .and_then(|provenance| match &provenance.source_identity {
                crate::workflow_attempts::TargetContentIdentity::IndexedSnapshot {
                    snapshot_hash,
                    ..
                } => Some(snapshot_hash.as_str()),
                _ => None,
            })
            .map(|hash| crate::identity::Blake3Hash::new(hash.to_string()))
            .transpose()?;
        let event = self.log.append(
            EventKind::VerificationRecorded,
            verification.actor.clone(),
            verification.verification_run_id.clone(),
            target_snapshot,
            verification.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    fn record_patch_attempt(&mut self, patch: PatchAttemptWrite) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let event = self.log.append(
            EventKind::PatchAttemptRecorded,
            patch.actor.clone(),
            Some(patch.patch_run_id.clone()),
            None,
            patch.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    fn record_patch_lifecycle(&mut self, lifecycle: PatchLifecycleWrite) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let record = lifecycle.record;
        let run_id = record
            .reverify_run_id
            .clone()
            .unwrap_or_else(|| record.patch_run_id.clone());
        let event = self.log.append(
            EventKind::PatchLifecycleRecorded,
            record.actor.clone(),
            Some(run_id),
            None,
            PatchLifecycleWrite { record }.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    fn record_checkpoint(&mut self) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let meta = self.projection.meta()?;
        let event = self.log.append(
            EventKind::ProjectionCheckpointed,
            "storage-writer",
            None,
            None,
            json!({
                "appliedSeqBeforeCheckpoint": meta.applied_seq,
                "logHeadBeforeCheckpoint": self.lifecycle.log_head(),
                "projectionGeneration": meta.generation,
            }),
        )?;
        let receipt = self.apply_appended_event(&event)?;
        self.log.write_checkpoint(&event)?;
        Ok(receipt)
    }

    fn compact_log(&mut self) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let meta = self.projection.meta()?;
        let log_head_before = self.lifecycle.log_head();
        self.lifecycle.begin_compaction()?;
        let event = self.log.append(
            EventKind::CompactionCompleted,
            "storage-writer",
            None,
            None,
            json!({
                "compactedThroughSeq": log_head_before,
                "appliedSeqBeforeCompaction": meta.applied_seq,
                "projectionGeneration": meta.generation,
                "segmentRollover": true,
            }),
        )?;
        let projection = self.projection.apply_event(&event)?;
        self.lifecycle.finish_compaction(event.seq, event.seq)?;
        self.log.write_checkpoint(&event)?;
        self.log.roll_segment()?;
        Ok(WriteReceipt {
            committed_seq: event.seq,
            event_hash: event.event_hash.as_str().to_string(),
            projection_generation: self.projection.meta()?.generation,
            projected_finding_id: projection.finding_id,
            projected_review_decision_id: projection.review_decision_id,
        })
    }

    fn record_finding_observation(
        &mut self,
        observation: ObservationWrite,
    ) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let event = self.log.append(
            EventKind::FindingObserved,
            observation.actor.clone(),
            Some(observation.run_id.clone()),
            None,
            observation.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    fn record_candidate_observation(
        &mut self,
        candidate: CandidateObservationWrite,
    ) -> Result<WriteReceipt> {
        self.record_finding_observation(candidate.into_observation_write())
    }

    fn record_snapshot_indexed(&mut self, snapshot: SnapshotWrite) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let event = self.log.append(
            EventKind::SnapshotIndexed,
            snapshot.actor.clone(),
            None,
            None,
            snapshot.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    fn record_file_indexed(&mut self, file: FileFactWrite) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let event = self.log.append(
            EventKind::FileIndexed,
            file.actor.clone(),
            None,
            None,
            file.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    fn record_file_deleted(&mut self, file: FileDeletedWrite) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let event = self.log.append(
            EventKind::FileDeleted,
            file.actor.clone(),
            None,
            None,
            file.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    fn record_attack_surface_indexed(
        &mut self,
        attack_surface: AttackSurfaceWrite,
    ) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let event = self.log.append(
            EventKind::AttackSurfaceIndexed,
            attack_surface.actor.clone(),
            attack_surface.run_id.clone(),
            None,
            attack_surface.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    fn rebuild_projection(&mut self) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        let previous = self.lifecycle;
        self.lifecycle.begin_rebuild()?;
        let rebuilt = self
            .log
            .read_all()
            .and_then(|events| self.projection.rebuild_from_events(&events));
        let applied_seq = match rebuilt {
            Ok(applied) => applied,
            Err(error) => {
                self.lifecycle = previous;
                return Err(error);
            }
        };
        self.lifecycle.finish_rebuild(applied_seq)?;
        Ok(WriteReceipt {
            committed_seq: applied_seq,
            event_hash: "rebuild-projection".to_string(),
            projection_generation: self.projection.meta()?.generation,
            projected_finding_id: None,
            projected_review_decision_id: None,
        })
    }

    fn shutdown_receipt(&mut self) -> Result<WriteReceipt> {
        self.lifecycle.begin_shutdown()?;
        let receipt = self.current_receipt("shutdown")?;
        self.lifecycle.finish_shutdown()?;
        Ok(receipt)
    }

    fn current_receipt(&self, label: &str) -> Result<WriteReceipt> {
        Ok(WriteReceipt {
            committed_seq: self.projection.meta()?.applied_seq,
            event_hash: label.to_string(),
            projection_generation: self.projection.meta()?.generation,
            projected_finding_id: None,
            projected_review_decision_id: None,
        })
    }

    #[cfg(test)]
    fn current_watermark(&self) -> Result<u64> {
        Ok(self.projection.meta()?.applied_seq)
    }

    fn apply_appended_event(&mut self, event: &EventEnvelope) -> Result<WriteReceipt> {
        #[cfg(test)]
        test_hooks::after_event_append(event);
        self.lifecycle.append_committed_event(event.seq)?;
        let projection = match self.projection.apply_event(event) {
            Ok(projection) => projection,
            Err(error) => {
                self.lifecycle.projection_failed();
                return Err(error);
            }
        };
        self.lifecycle.projection_advanced(event.seq)?;
        Ok(WriteReceipt {
            committed_seq: event.seq,
            event_hash: event.event_hash.as_str().to_string(),
            projection_generation: self.projection.meta()?.generation,
            projected_finding_id: projection.finding_id,
            projected_review_decision_id: projection.review_decision_id,
        })
    }

    fn replay_projection(&mut self) -> Result<()> {
        if self.lifecycle.state() != WriterActorState::Replaying {
            return Ok(());
        }
        let applied = self.lifecycle.applied_seq();
        for event in self.log.read_all()? {
            if event.seq <= applied {
                continue;
            }
            self.projection.apply_event(&event)?;
            self.lifecycle.projection_advanced(event.seq)?;
        }
        Ok(())
    }
}

pub(crate) struct StorageWriterSession {
    writer: StorageWriter,
}

impl StorageWriterSession {
    pub(crate) fn open(
        log_dir: impl AsRef<Path>,
        projection_path: impl AsRef<Path>,
    ) -> Result<Self> {
        Ok(Self {
            writer: StorageWriter::open(log_dir, projection_path)?,
        })
    }

    pub(crate) fn commit_many(
        &mut self,
        commands: Vec<WriterCommand>,
    ) -> Result<Vec<WriteReceipt>> {
        commands
            .into_iter()
            .map(|command| self.writer.execute_command(command))
            .collect()
    }
}

fn initialize_workspace_storage(log_dir: &Path, projection_path: &Path) -> Result<()> {
    let log_root = validate_workspace_storage_path(log_dir)?;
    let projection_root = validate_workspace_storage_path(projection_path)?;
    if let Some(root) = log_root.as_deref() {
        crate::workspace::initialize_workspace_state(root)?;
    }
    if projection_root != log_root {
        if let Some(root) = projection_root.as_deref() {
            crate::workspace::initialize_workspace_state(root)?;
        }
    }
    Ok(())
}

fn validate_workspace_storage_path(path: &Path) -> Result<Option<PathBuf>> {
    let Some(state_dir) = workspace_state_ancestor(path) else {
        return Ok(None);
    };
    let workspace_root = state_dir
        .parent()
        .and_then(Path::parent)
        .expect("workspace state ancestor includes target root");
    let relative = path.strip_prefix(workspace_root)?;
    crate::workspace::validated_workspace_descendant(workspace_root, relative)?;
    std::fs::canonicalize(workspace_root)
        .with_context(|| {
            format!(
                "Could not resolve storage workspace root {}",
                workspace_root.display()
            )
        })
        .map(Some)
}

fn normalize_storage_paths(log_dir: &Path, projection_path: &Path) -> Result<(PathBuf, PathBuf)> {
    if log_dir.is_absolute() && projection_path.is_absolute() {
        return Ok((log_dir.to_path_buf(), projection_path.to_path_buf()));
    }
    let current = std::env::current_dir()
        .context("Could not resolve relative storage paths from the current directory")?;
    Ok((
        absolute_from(&current, log_dir),
        absolute_from(&current, projection_path),
    ))
}

fn absolute_from(current: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        current.join(path)
    }
}

fn workspace_state_ancestor(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|ancestor| {
            ancestor.file_name().and_then(|name| name.to_str())
                == Some(crate::workspace::WORKSPACE_STATE_VERSION_DIR)
                && ancestor
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    == Some(crate::workspace::KUZUSHI_STATE_DIR)
        })
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod process_stress_tests;
#[cfg(test)]
mod tests;
