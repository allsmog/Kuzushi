use super::budget::OutstandingEventBudget;
use super::file_io::{open_existing_secure_file, write_pending_once};
use super::WriterCommand;
use crate::session_transcript::{SessionRecorderHealth, SessionRecorderStatus};
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::fs::File;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;

pub(super) fn spawn_writer(
    path: PathBuf,
    file: File,
    receiver: Receiver<WriterCommand>,
    status: Arc<Mutex<SessionRecorderStatus>>,
    event_budget: Arc<OutstandingEventBudget>,
) -> Result<()> {
    thread::Builder::new()
        .name("kuzushi-session-writer".to_string())
        .spawn(move || writer_loop(path, file, receiver, status, event_budget))
        .context("could not spawn session transcript writer")?;
    Ok(())
}

pub(super) fn try_send_append(
    sender: &SyncSender<WriterCommand>,
    command: WriterCommand,
    status: &Arc<Mutex<SessionRecorderStatus>>,
    event_budget: &Arc<OutstandingEventBudget>,
) -> Result<()> {
    if !event_budget.try_reserve() {
        return note_enqueue_error(status, "session transcript queue is full");
    }
    note_pending(status, event_budget.pending());
    match sender.try_send(command) {
        Ok(()) => Ok(()),
        Err(mpsc::TrySendError::Full(_)) => reject_reserved_event(
            status,
            event_budget,
            "session transcript queue is full",
        ),
        Err(mpsc::TrySendError::Disconnected(_)) => reject_reserved_event(
            status,
            event_budget,
            "session transcript writer stopped",
        ),
    }
}

fn writer_loop(
    path: PathBuf,
    file: File,
    receiver: Receiver<WriterCommand>,
    status: Arc<Mutex<SessionRecorderStatus>>,
    event_budget: Arc<OutstandingEventBudget>,
) {
    let mut state = WriterState::new(path, file, status, event_budget);
    while let Ok(command) = receiver.recv() {
        if state.handle(command) {
            return;
        }
    }
    state.close();
}

pub(super) struct WriterState {
    path: PathBuf,
    file: Option<File>,
    pending: VecDeque<PendingRecord>,
    status: Arc<Mutex<SessionRecorderStatus>>,
    event_budget: Arc<OutstandingEventBudget>,
}

struct PendingRecord {
    sequence: u64,
    body: Vec<u8>,
    offset: usize,
}

impl WriterState {
    pub(super) fn new(
        path: PathBuf,
        file: File,
        status: Arc<Mutex<SessionRecorderStatus>>,
        event_budget: Arc<OutstandingEventBudget>,
    ) -> Self {
        Self {
            path,
            file: Some(file),
            pending: VecDeque::new(),
            status,
            event_budget,
        }
    }

    fn handle(&mut self, command: WriterCommand) -> bool {
        match command {
            WriterCommand::Append { sequence, body } => {
                self.queue(sequence, body);
                let _ = self.drain_with_retry();
                false
            }
            WriterCommand::Flush(reply) => {
                let _ = reply.send(self.drain_result());
                false
            }
            WriterCommand::Shutdown(reply) => {
                let _ = reply.send(self.drain_result());
                self.close();
                true
            }
        }
    }

    pub(super) fn queue(&mut self, sequence: u64, body: Vec<u8>) {
        self.pending.push_back(PendingRecord {
            sequence,
            body,
            offset: 0,
        });
        self.update_pending();
    }

    fn drain_result(&mut self) -> std::result::Result<(), String> {
        self.drain_with_retry().map_err(|error| error.to_string())
    }

    pub(super) fn drain_with_retry(&mut self) -> Result<()> {
        if let Err(first) = self.drain() {
            self.note_error(&first);
            self.file = None;
            if let Err(second) = self.drain() {
                self.note_error(&second);
                return Err(second);
            }
        }
        self.note_recovered();
        Ok(())
    }

    fn drain(&mut self) -> Result<()> {
        while !self.pending.is_empty() {
            self.write_pending_front()?;
            let sequence = self.pending.front().expect("pending record exists").sequence;
            self.pending.pop_front();
            self.event_budget.release();
            self.note_flushed(sequence);
        }
        Ok(())
    }

    fn write_pending_front(&mut self) -> Result<()> {
        loop {
            let (body, mut offset) = self.pending_body_and_offset();
            let complete = write_pending_once(self.open_file()?, &body, &mut offset)?;
            self.pending.front_mut().expect("pending record exists").offset = offset;
            if complete {
                return Ok(());
            }
        }
    }

    fn pending_body_and_offset(&self) -> (Vec<u8>, usize) {
        let pending = self.pending.front().expect("pending record exists");
        (pending.body.clone(), pending.offset)
    }

    fn open_file(&mut self) -> Result<&mut File> {
        if self.file.is_none() {
            self.file = Some(open_existing_secure_file(&self.path)?);
        }
        Ok(self.file.as_mut().expect("session file opened"))
    }

    fn note_flushed(&self, sequence: u64) {
        let mut status = self.status.lock().expect("session status poisoned");
        status.last_flushed_sequence = sequence;
        status.pending_records = self.event_budget.pending();
    }

    fn update_pending(&self) {
        self.status
            .lock()
            .expect("session status poisoned")
            .pending_records = self.event_budget.pending();
    }

    fn note_error(&self, error: &anyhow::Error) {
        let mut status = self.status.lock().expect("session status poisoned");
        status.health = SessionRecorderHealth::Warning;
        status.last_error = Some(format!("session transcript persistence failed: {error}"));
        status.pending_records = self.event_budget.pending();
    }

    pub(super) fn note_recovered(&self) {
        let mut status = self.status.lock().expect("session status poisoned");
        if status.health != SessionRecorderHealth::Closed {
            status.health = SessionRecorderHealth::Healthy;
            status.last_error = None;
        }
    }

    fn close(&self) {
        self.status.lock().expect("session status poisoned").health =
            SessionRecorderHealth::Closed;
    }

    #[cfg(test)]
    pub(super) fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

fn reject_reserved_event(
    status: &Arc<Mutex<SessionRecorderStatus>>,
    event_budget: &OutstandingEventBudget,
    message: &'static str,
) -> Result<()> {
    event_budget.release();
    note_pending(status, event_budget.pending());
    note_enqueue_error(status, message)
}

fn note_pending(status: &Arc<Mutex<SessionRecorderStatus>>, pending: usize) {
    status.lock().expect("session status poisoned").pending_records = pending;
}

fn note_enqueue_error(
    status: &Arc<Mutex<SessionRecorderStatus>>,
    message: &'static str,
) -> Result<()> {
    let mut recorder_status = status.lock().expect("session status poisoned");
    recorder_status.health = SessionRecorderHealth::Warning;
    recorder_status.last_error = Some(message.to_string());
    anyhow::bail!(message)
}
