use super::{same_watcher_key, ControlCommand, WriteLane, WriterCommand};
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::path::PathBuf;
use tokio::sync::{mpsc as tokio_mpsc, oneshot};

pub(super) struct ActorReceivers {
    pub(super) control: tokio_mpsc::Receiver<ActorEnvelope>,
    pub(super) decisions: tokio_mpsc::Receiver<ActorEnvelope>,
    pub(super) watcher: tokio_mpsc::Receiver<ActorEnvelope>,
}

#[derive(Debug)]
pub(super) struct ActorEnvelope {
    command_id: uuid::Uuid,
    command: WriterCommand,
    reply: oneshot::Sender<Result<super::super::WriteReceipt>>,
}

impl ActorEnvelope {
    pub(super) fn new(
        command: WriterCommand,
        reply: oneshot::Sender<Result<super::super::WriteReceipt>>,
    ) -> Self {
        Self {
            command_id: uuid::Uuid::new_v4(),
            command,
            reply,
        }
    }
}

pub(super) async fn run_actor(
    log_dir: PathBuf,
    projection_path: PathBuf,
    decision_budget: usize,
    mut rx: ActorReceivers,
) -> Result<()> {
    let writer = super::super::StorageWriter::open(log_dir, projection_path)?;
    RunningActor::new(writer, decision_budget).run(&mut rx).await
}

pub(super) fn run_actor_blocking(
    log_dir: PathBuf,
    projection_path: PathBuf,
    commands: Vec<WriterCommand>,
) -> Result<Vec<super::super::WriteReceipt>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not create storage writer actor runtime")?;
    runtime.block_on(dispatch_blocking_commands(
        log_dir,
        projection_path,
        commands,
    ))
}

async fn dispatch_blocking_commands(
    log_dir: PathBuf,
    projection_path: PathBuf,
    commands: Vec<WriterCommand>,
) -> Result<Vec<super::super::WriteReceipt>> {
    let actor =
        super::StorageWriterActor::spawn(log_dir, projection_path, super::StorageWriterActorConfig::default());
    let mut receipts = Vec::with_capacity(commands.len());
    let command_result = dispatch_commands(&actor, commands, &mut receipts).await;
    let shutdown_result = actor.shutdown().await;
    command_result?;
    shutdown_result?;
    Ok(receipts)
}

async fn dispatch_commands(
    actor: &super::StorageWriterActorHandle,
    commands: Vec<WriterCommand>,
    receipts: &mut Vec<super::super::WriteReceipt>,
) -> Result<()> {
    for command in commands {
        receipts.push(actor.dispatch(command).await?);
    }
    Ok(())
}

struct RunningActor {
    writer: super::super::StorageWriter,
    queues: ActorQueues,
}

impl RunningActor {
    fn new(writer: super::super::StorageWriter, decision_budget: usize) -> Self {
        Self {
            writer,
            queues: ActorQueues::new(decision_budget),
        }
    }

    async fn run(&mut self, rx: &mut ActorReceivers) -> Result<()> {
        while self.advance(rx).await {}
        Ok(())
    }

    async fn advance(&mut self, rx: &mut ActorReceivers) -> bool {
        drain_ready(rx, &mut self.queues);
        if self.process_ready_batch() {
            return true;
        }
        if self.finish_if_shutdown_ready() {
            return false;
        }
        self.receive_or_finish(rx).await
    }

    fn process_ready_batch(&mut self) -> bool {
        let batch = self.queues.next_batch();
        if batch.is_empty() {
            return false;
        }
        for envelope in batch {
            self.process_envelope(envelope);
        }
        true
    }

    fn finish_if_shutdown_ready(&mut self) -> bool {
        if self.queues.shutdown.is_none() || !self.queues.is_empty() {
            return false;
        }
        self.finish_shutdown();
        true
    }

    async fn receive_or_finish(&mut self, rx: &mut ActorReceivers) -> bool {
        let Some(envelope) = receive_next(rx).await else {
            self.finish_shutdown();
            return false;
        };
        self.queues.push(envelope);
        true
    }

    fn process_envelope(&mut self, envelope: ActorEnvelope) {
        if matches!(
            &envelope.command,
            WriterCommand::Control(ControlCommand::Shutdown)
        ) {
            self.queue_shutdown_reply(envelope.reply);
            return;
        }
        let result = self.writer.execute_command(envelope.command);
        let _ = envelope.reply.send(result);
    }

    fn queue_shutdown_reply(
        &mut self,
        reply: oneshot::Sender<Result<super::super::WriteReceipt>>,
    ) {
        if self.queues.shutdown.is_some() {
            let _ = reply.send(Err(anyhow::anyhow!(
                "storage writer actor is already shutting down"
            )));
        } else {
            self.queues.shutdown = Some(reply);
        }
    }

    fn finish_shutdown(&mut self) {
        let Some(reply) = self.queues.shutdown.take() else {
            return;
        };
        let _ = reply.send(self.writer.shutdown_receipt());
    }
}

struct ActorQueues {
    decision_budget: usize,
    control: VecDeque<ActorEnvelope>,
    decisions: VecDeque<ActorEnvelope>,
    watcher: VecDeque<ActorEnvelope>,
    shutdown: Option<oneshot::Sender<Result<super::super::WriteReceipt>>>,
}

impl ActorQueues {
    fn new(decision_budget: usize) -> Self {
        Self {
            decision_budget: decision_budget.max(1),
            control: VecDeque::new(),
            decisions: VecDeque::new(),
            watcher: VecDeque::new(),
            shutdown: None,
        }
    }

    fn push(&mut self, envelope: ActorEnvelope) {
        match envelope.command.lane() {
            WriteLane::Control => self.control.push_back(envelope),
            WriteLane::Decision => self.decisions.push_back(envelope),
            WriteLane::Watcher => self.push_watcher(envelope),
        }
    }

    fn push_watcher(&mut self, envelope: ActorEnvelope) {
        if !envelope.command.can_be_coalesced() {
            self.watcher.push_back(envelope);
            return;
        }
        if let Some(existing) = self
            .watcher
            .iter_mut()
            .find(|existing| same_watcher_key(&existing.command, &envelope.command))
        {
            reject_coalesced_watcher(std::mem::replace(existing, envelope));
            return;
        }
        self.watcher.push_back(envelope);
    }

    fn next_batch(&mut self) -> Vec<ActorEnvelope> {
        let mut batch = Vec::new();
        self.drain_control(&mut batch);
        self.drain_decisions(&mut batch);
        self.drain_one_watcher(&mut batch);
        batch
    }

    fn is_empty(&self) -> bool {
        self.control.is_empty() && self.decisions.is_empty() && self.watcher.is_empty()
    }

    fn drain_control(&mut self, batch: &mut Vec<ActorEnvelope>) {
        while let Some(envelope) = self.control.pop_front() {
            batch.push(envelope);
        }
    }

    fn drain_decisions(&mut self, batch: &mut Vec<ActorEnvelope>) {
        for _ in 0..self.decision_budget {
            let Some(envelope) = self.decisions.pop_front() else {
                break;
            };
            batch.push(envelope);
        }
    }

    fn drain_one_watcher(&mut self, batch: &mut Vec<ActorEnvelope>) {
        if let Some(envelope) = self.watcher.pop_front() {
            batch.push(envelope);
        }
    }
}

fn reject_coalesced_watcher(envelope: ActorEnvelope) {
    let _ = envelope.reply.send(Err(anyhow::anyhow!(
        "watcher command {} was coalesced by a newer update",
        envelope.command_id
    )));
}

fn drain_ready(rx: &mut ActorReceivers, queues: &mut ActorQueues) {
    drain_lane(&mut rx.control, queues);
    drain_lane(&mut rx.decisions, queues);
    drain_lane(&mut rx.watcher, queues);
}

fn drain_lane(lane: &mut tokio_mpsc::Receiver<ActorEnvelope>, queues: &mut ActorQueues) {
    while let Ok(envelope) = lane.try_recv() {
        queues.push(envelope);
    }
}

async fn receive_next(rx: &mut ActorReceivers) -> Option<ActorEnvelope> {
    tokio::select! {
        biased;
        Some(envelope) = rx.control.recv() => Some(envelope),
        Some(envelope) = rx.decisions.recv() => Some(envelope),
        Some(envelope) = rx.watcher.recv() => Some(envelope),
        else => None,
    }
}
