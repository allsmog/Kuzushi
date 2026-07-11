use super::{
    lifecycle::require_state, AuditWrite, ControlCommand, DecisionCommand, FindingLifecycleWrite,
    RunLifecycleWrite, StorageWriter, WatcherCommand, WriteReceipt, WriterActorState,
    WriterCommand,
};
use crate::event_log::EventKind;
use anyhow::{bail, Result};

impl StorageWriter {
    pub(in crate::storage_v3::writer_actor) fn execute_command(
        &mut self,
        command: WriterCommand,
    ) -> Result<WriteReceipt> {
        match command {
            WriterCommand::Control(command) => self.execute_control_command(command),
            WriterCommand::Decision(command) => self.execute_decision_command(command),
            WriterCommand::Watcher(command) => self.execute_watcher_command(command),
        }
    }

    fn execute_control_command(&mut self, command: ControlCommand) -> Result<WriteReceipt> {
        match command {
            ControlCommand::Barrier => self.current_receipt("barrier"),
            ControlCommand::Checkpoint => self.record_checkpoint(),
            ControlCommand::RebuildProjection => self.rebuild_projection(),
            ControlCommand::Compact => self.compact_log(),
            ControlCommand::Shutdown => self.shutdown_receipt(),
        }
    }

    fn execute_decision_command(&mut self, command: DecisionCommand) -> Result<WriteReceipt> {
        match command {
            DecisionCommand::ReviewDecision(decision) => self.record_review_decision(decision),
            DecisionCommand::RecordVerification(verification) => {
                self.record_verification(verification)
            }
            DecisionCommand::RecordPatchAttempt(patch) => self.record_patch_attempt(patch),
            DecisionCommand::RecordAudit(audit) => self.record_audit_event(audit),
            DecisionCommand::RecordRunLifecycle(run) => self.record_run_lifecycle(run),
            DecisionCommand::RecordFindingLifecycle(finding) => {
                self.record_finding_lifecycle(finding)
            }
            DecisionCommand::RekeyFinding(rekey) => self.record_rekey(rekey),
        }
    }

    fn execute_watcher_command(&mut self, command: WatcherCommand) -> Result<WriteReceipt> {
        match command {
            WatcherCommand::SnapshotIndexed(snapshot) => self.record_snapshot_indexed(snapshot),
            WatcherCommand::FileIndexed(file) => self.record_file_indexed(file),
            WatcherCommand::FileDeleted(file) => self.record_file_deleted(file),
            WatcherCommand::AttackSurfaceIndexed(attack_surface) => {
                self.record_attack_surface_indexed(attack_surface)
            }
            WatcherCommand::FindingObservation(observation) => {
                self.record_finding_observation(observation)
            }
            WatcherCommand::CandidateObservation(candidate) => {
                self.record_candidate_observation(candidate)
            }
            WatcherCommand::FileFactsChanged { .. }
            | WatcherCommand::WorkspaceChanged { .. }
            | WatcherCommand::ObservationBatch { .. } => {
                bail!("watcher marker commands must be materialized before writer commit")
            }
        }
    }

    pub(in crate::storage_v3::writer_actor) fn record_audit_event(
        &mut self,
        audit: AuditWrite,
    ) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        require_audit_event_kind(audit.event_kind)?;
        let event = self.log.append(
            audit.event_kind,
            audit.actor.clone(),
            audit.run_id.clone(),
            None,
            audit.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    pub(in crate::storage_v3::writer_actor) fn record_run_lifecycle(
        &mut self,
        run: RunLifecycleWrite,
    ) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        require_run_lifecycle_event_kind(run.event_kind)?;
        let event = self.log.append(
            run.event_kind,
            run.actor.clone(),
            Some(run.run_id.clone()),
            None,
            run.payload(),
        )?;
        self.apply_appended_event(&event)
    }

    pub(in crate::storage_v3::writer_actor) fn record_finding_lifecycle(
        &mut self,
        finding: FindingLifecycleWrite,
    ) -> Result<WriteReceipt> {
        require_state(self.lifecycle.state(), WriterActorState::Live)?;
        require_finding_lifecycle_event_kind(finding.event_kind)?;
        let event = self.log.append(
            finding.event_kind,
            finding.actor.clone(),
            finding.run_id.clone(),
            None,
            finding.payload(),
        )?;
        self.apply_appended_event(&event)
    }
}

fn require_audit_event_kind(event_kind: EventKind) -> Result<()> {
    if matches!(
        event_kind,
        EventKind::DiagnosticRecorded
            | EventKind::ModelCallRecorded
            | EventKind::PluginInvocationRecorded
    ) {
        return Ok(());
    }
    bail!(
        "event kind {} is not a writer audit event",
        event_kind.as_str()
    )
}

fn require_run_lifecycle_event_kind(event_kind: EventKind) -> Result<()> {
    if matches!(
        event_kind,
        EventKind::RunStarted | EventKind::RunCompleted | EventKind::RunFailed
    ) {
        return Ok(());
    }
    bail!(
        "event kind {} is not a run lifecycle event",
        event_kind.as_str()
    )
}

fn require_finding_lifecycle_event_kind(event_kind: EventKind) -> Result<()> {
    if matches!(
        event_kind,
        EventKind::FindingDisappeared
            | EventKind::FindingReopened
            | EventKind::SuppressionAdded
            | EventKind::SuppressionExpired
            | EventKind::SuppressionRemoved
    ) {
        return Ok(());
    }
    bail!(
        "event kind {} is not a finding lifecycle event",
        event_kind.as_str()
    )
}
