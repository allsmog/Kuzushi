use super::{
    AttackSurfaceWrite, AuditWrite, CandidateObservationWrite, DecisionWrite, FileDeletedWrite,
    FileFactWrite, FindingLifecycleWrite, ObservationWrite, PatchAttemptWrite, PatchLifecycleWrite,
    RekeyWrite, ReviewSessionWrite, RunLifecycleWrite, SnapshotWrite, VerificationWrite,
};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::VecDeque;
use std::path::PathBuf;
use tokio::sync::{mpsc as tokio_mpsc, oneshot};

mod actor_loop;
use actor_loop::{run_actor, ActorEnvelope, ActorReceivers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteLane {
    Control,
    Decision,
    Watcher,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCommand {
    Checkpoint,
    RebuildProjection,
    Compact,
    Barrier,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DecisionCommand {
    ReviewDecision(DecisionWrite),
    /// Ordered with decisions on purpose: a session and the verdict it
    /// precedes are one causal chain of operator review.
    ReviewSessionStarted(ReviewSessionWrite),
    RecordVerification(VerificationWrite),
    RecordPatchAttempt(PatchAttemptWrite),
    RecordPatchLifecycle(PatchLifecycleWrite),
    RecordAudit(AuditWrite),
    RecordRunLifecycle(RunLifecycleWrite),
    RecordFindingLifecycle(FindingLifecycleWrite),
    RekeyFinding(RekeyWrite),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherCommand {
    FileFactsChanged { path: String },
    WorkspaceChanged { summary: String },
    SnapshotIndexed(SnapshotWrite),
    FileIndexed(FileFactWrite),
    FileDeleted(FileDeletedWrite),
    AttackSurfaceIndexed(AttackSurfaceWrite),
    FindingObservation(ObservationWrite),
    CandidateObservation(CandidateObservationWrite),
    ObservationBatch { payload: Value },
}

#[derive(Debug, Clone, PartialEq)]
pub enum WriterCommand {
    Control(ControlCommand),
    Decision(DecisionCommand),
    Watcher(WatcherCommand),
}

impl WriterCommand {
    pub fn lane(&self) -> WriteLane {
        match self {
            Self::Control(_) => WriteLane::Control,
            Self::Decision(_) => WriteLane::Decision,
            Self::Watcher(_) => WriteLane::Watcher,
        }
    }

    pub fn can_be_coalesced(&self) -> bool {
        matches!(
            self,
            Self::Watcher(
                WatcherCommand::FileFactsChanged { .. } | WatcherCommand::WorkspaceChanged { .. }
            )
        )
    }
}

#[derive(Debug)]
pub struct WriterLaneScheduler {
    decision_budget: usize,
    control: VecDeque<WriterCommand>,
    decisions: VecDeque<WriterCommand>,
    watcher: VecDeque<WriterCommand>,
}

impl WriterLaneScheduler {
    pub fn new(decision_budget: usize) -> Self {
        Self {
            decision_budget: decision_budget.max(1),
            control: VecDeque::new(),
            decisions: VecDeque::new(),
            watcher: VecDeque::new(),
        }
    }

    pub fn push(&mut self, command: WriterCommand) {
        match command.lane() {
            WriteLane::Control => self.control.push_back(command),
            WriteLane::Decision => self.decisions.push_back(command),
            WriteLane::Watcher => self.push_watcher(command),
        }
    }

    pub fn next_batch(&mut self) -> Vec<WriterCommand> {
        let mut batch = Vec::new();
        while let Some(command) = self.control.pop_front() {
            batch.push(command);
        }
        for _ in 0..self.decision_budget {
            let Some(command) = self.decisions.pop_front() else {
                break;
            };
            batch.push(command);
        }
        if let Some(command) = self.watcher.pop_front() {
            batch.push(command);
        }
        batch
    }

    fn push_watcher(&mut self, command: WriterCommand) {
        if !command.can_be_coalesced() {
            self.watcher.push_back(command);
            return;
        }
        if let Some(existing) = self
            .watcher
            .iter_mut()
            .find(|existing| same_watcher_key(existing, &command))
        {
            *existing = command;
            return;
        }
        self.watcher.push_back(command);
    }
}

fn same_watcher_key(left: &WriterCommand, right: &WriterCommand) -> bool {
    match (left, right) {
        (
            WriterCommand::Watcher(WatcherCommand::FileFactsChanged { path: left }),
            WriterCommand::Watcher(WatcherCommand::FileFactsChanged { path: right }),
        ) => left == right,
        (
            WriterCommand::Watcher(WatcherCommand::WorkspaceChanged { summary: left }),
            WriterCommand::Watcher(WatcherCommand::WorkspaceChanged { summary: right }),
        ) => left == right,
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageWriterActorConfig {
    pub decision_budget: usize,
    pub control_capacity: usize,
    pub decision_capacity: usize,
    pub watcher_capacity: usize,
}

impl Default for StorageWriterActorConfig {
    fn default() -> Self {
        Self {
            decision_budget: 8,
            control_capacity: 32,
            decision_capacity: 256,
            watcher_capacity: 4096,
        }
    }
}

pub struct StorageWriterActor;

impl StorageWriterActor {
    pub fn spawn(
        log_dir: impl Into<PathBuf>,
        projection_path: impl Into<PathBuf>,
        config: StorageWriterActorConfig,
    ) -> StorageWriterActorHandle {
        let (control_tx, control_rx) = tokio_mpsc::channel(config.control_capacity.max(1));
        let (decision_tx, decision_rx) = tokio_mpsc::channel(config.decision_capacity.max(1));
        let (watcher_tx, watcher_rx) = tokio_mpsc::channel(config.watcher_capacity.max(1));
        let log_dir = log_dir.into();
        let projection_path = projection_path.into();
        let join = tokio::spawn(async move {
            run_actor(
                log_dir,
                projection_path,
                config.decision_budget,
                ActorReceivers {
                    control: control_rx,
                    decisions: decision_rx,
                    watcher: watcher_rx,
                },
            )
            .await
        });
        StorageWriterActorHandle {
            control_tx,
            decision_tx,
            watcher_tx,
            join,
        }
    }

    pub fn commit_blocking(
        log_dir: impl Into<PathBuf>,
        projection_path: impl Into<PathBuf>,
        command: WriterCommand,
    ) -> Result<super::WriteReceipt> {
        let mut receipts = Self::commit_blocking_many(log_dir, projection_path, vec![command])?;
        receipts
            .pop()
            .context("storage writer actor produced no receipt")
    }

    pub fn commit_blocking_many(
        log_dir: impl Into<PathBuf>,
        projection_path: impl Into<PathBuf>,
        commands: Vec<WriterCommand>,
    ) -> Result<Vec<super::WriteReceipt>> {
        let mut session =
            super::StorageWriterSession::open(log_dir.into(), projection_path.into())?;
        session.commit_many(commands)
    }
}

#[derive(Debug)]
pub struct StorageWriterActorHandle {
    control_tx: tokio_mpsc::Sender<ActorEnvelope>,
    decision_tx: tokio_mpsc::Sender<ActorEnvelope>,
    watcher_tx: tokio_mpsc::Sender<ActorEnvelope>,
    join: tokio::task::JoinHandle<Result<()>>,
}

impl StorageWriterActorHandle {
    pub async fn dispatch(&self, command: WriterCommand) -> Result<super::WriteReceipt> {
        match command {
            WriterCommand::Control(command) => self.control(command).await,
            WriterCommand::Decision(command) => self.decision(command).await,
            WriterCommand::Watcher(command) => self.watcher(command).await,
        }
    }

    pub async fn control(&self, command: ControlCommand) -> Result<super::WriteReceipt> {
        self.send(&self.control_tx, WriterCommand::Control(command))
            .await
    }

    pub async fn decision(&self, command: DecisionCommand) -> Result<super::WriteReceipt> {
        self.send(&self.decision_tx, WriterCommand::Decision(command))
            .await
    }

    pub async fn try_decision(&self, command: DecisionCommand) -> Result<super::WriteReceipt> {
        self.try_send(&self.decision_tx, WriterCommand::Decision(command))
            .await
    }

    pub async fn watcher(&self, command: WatcherCommand) -> Result<super::WriteReceipt> {
        self.send(&self.watcher_tx, WriterCommand::Watcher(command))
            .await
    }

    pub async fn shutdown(self) -> Result<()> {
        let _ = self.control(ControlCommand::Shutdown).await?;
        drop(self.control_tx);
        drop(self.decision_tx);
        drop(self.watcher_tx);
        self.join.await.context("storage writer actor panicked")?
    }

    async fn send(
        &self,
        tx: &tokio_mpsc::Sender<ActorEnvelope>,
        command: WriterCommand,
    ) -> Result<super::WriteReceipt> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(ActorEnvelope::new(command, reply_tx))
            .await
            .context("storage writer actor is stopped")?;
        reply_rx
            .await
            .context("storage writer actor dropped reply")?
    }

    async fn try_send(
        &self,
        tx: &tokio_mpsc::Sender<ActorEnvelope>,
        command: WriterCommand,
    ) -> Result<super::WriteReceipt> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.try_send(ActorEnvelope::new(command, reply_tx))
            .context("storage writer actor lane is busy")?;
        reply_rx
            .await
            .context("storage writer actor dropped reply")?
    }
}
