use super::ProjectionDb;
use crate::event_log::{EventEnvelope, EventKind, EventLog};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;

mod commands;
mod dispatch;
mod lifecycle;
mod staleness;
mod writes;

pub use commands::{StorageWriterActor, StorageWriterActorConfig, StorageWriterActorHandle};
pub use commands::{
    ControlCommand, DecisionCommand, WatcherCommand, WriteEnvelope, WriteLane, WriterCommand,
    WriterLaneScheduler,
};
use lifecycle::require_state;
pub use lifecycle::{WriterActorState, WriterLifecycle};
pub use writes::{
    AttackSurfaceWrite, AuditWrite, CandidateObservationWrite, DecisionWrite, FileDeletedWrite,
    FileFactWrite, FindingLifecycleWrite, ObservationWrite, PatchAttemptWrite, RekeyWrite,
    RunLifecycleWrite, SnapshotWrite, VerificationWrite,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteReceipt {
    pub committed_seq: u64,
    pub event_hash: String,
    pub projection_generation: u64,
    pub projected_review_decision_id: Option<i64>,
}

struct StorageWriter {
    log: EventLog,
    projection: ProjectionDb,
    lifecycle: WriterLifecycle,
}

impl StorageWriter {
    fn open(log_dir: impl AsRef<Path>, projection_path: impl AsRef<Path>) -> Result<Self> {
        let log = EventLog::open(log_dir)?;
        log.verify_chain()?;
        let projection = ProjectionDb::open(projection_path)?;
        let mut lifecycle = WriterLifecycle::recovering();
        lifecycle.recover(log.head_seq()?, projection.meta()?.applied_seq)?;
        let mut writer = Self {
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
        let event = self.log.append(
            EventKind::VerificationRecorded,
            verification.actor.clone(),
            None,
            None,
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
            projected_review_decision_id: projection.review_decision_id,
        })
    }

    fn record_finding_observation(&mut self, observation: ObservationWrite) -> Result<WriteReceipt> {
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
        self.lifecycle.begin_rebuild()?;
        self.projection.reset_for_rebuild()?;
        let mut applied_seq = 0;
        for event in self.log.read_all()? {
            self.projection.apply_event(&event)?;
            applied_seq = event.seq;
        }
        self.lifecycle.finish_rebuild(applied_seq)?;
        Ok(WriteReceipt {
            committed_seq: applied_seq,
            event_hash: "rebuild-projection".to_string(),
            projection_generation: self.projection.meta()?.generation,
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
            projected_review_decision_id: None,
        })
    }

    #[cfg(test)]
    fn current_watermark(&self) -> Result<u64> {
        Ok(self.projection.meta()?.applied_seq)
    }

    fn apply_appended_event(&mut self, event: &EventEnvelope) -> Result<WriteReceipt> {
        self.lifecycle.append_committed_event(event.seq)?;
        let projection = self.projection.apply_event(event)?;
        self.lifecycle.projection_advanced(event.seq)?;
        Ok(WriteReceipt {
            committed_seq: event.seq,
            event_hash: event.event_hash.as_str().to_string(),
            projection_generation: self.projection.meta()?.generation,
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

#[cfg(test)]
mod tests;
