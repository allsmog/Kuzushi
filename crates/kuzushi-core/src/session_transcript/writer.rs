use super::model::{
    SessionEvent, SessionMetadata, SessionRecord, SessionRecorderHealth, SessionRecorderStatus,
};
use super::redaction::{encode_bounded, event_parts, metadata_payload};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

mod background;
mod budget;
mod file_io;

use background::{spawn_writer, try_send_append};
use budget::OutstandingEventBudget;
use file_io::create_secure_file;

const WRITER_QUEUE_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct SessionRecorder {
    inner: Arc<RecorderInner>,
}

struct RecorderInner {
    session_id: String,
    path: PathBuf,
    sender: Mutex<Option<SyncSender<WriterCommand>>>,
    cursor: Mutex<RecordCursor>,
    status: Arc<Mutex<SessionRecorderStatus>>,
    event_budget: Arc<OutstandingEventBudget>,
}

struct RecordCursor {
    next_sequence: u64,
    parent_event_id: Option<String>,
}

enum WriterCommand {
    Append { sequence: u64, body: Vec<u8> },
    Flush(mpsc::SyncSender<std::result::Result<(), String>>),
    Shutdown(mpsc::SyncSender<std::result::Result<(), String>>),
}

impl SessionRecorder {
    pub(crate) fn start(
        path: PathBuf,
        session_id: String,
        metadata: SessionMetadata,
    ) -> Result<Self> {
        let metadata_id = Uuid::new_v4().to_string();
        let record = metadata_record(&session_id, &metadata_id, metadata)?;
        let mut file = create_secure_file(&path)?;
        file.write_all(&encode_bounded(&record)?)?;
        file.flush()?;
        let status = initial_status(&session_id, &path);
        let event_budget = Arc::new(OutstandingEventBudget::new(WRITER_QUEUE_CAPACITY));
        let (sender, receiver) = mpsc::sync_channel(WRITER_QUEUE_CAPACITY);
        spawn_writer(
            path.clone(),
            file,
            receiver,
            Arc::clone(&status),
            Arc::clone(&event_budget),
        )?;
        Ok(Self {
            inner: Arc::new(RecorderInner {
                session_id,
                path,
                sender: Mutex::new(Some(sender)),
                cursor: Mutex::new(RecordCursor {
                    next_sequence: 1,
                    parent_event_id: Some(metadata_id),
                }),
                status,
                event_budget,
            }),
        })
    }

    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    pub fn record(&self, event: SessionEvent) -> Result<()> {
        let mut cursor = self.inner.cursor.lock().expect("session cursor poisoned");
        let record = event_record(self.session_id(), &cursor, event)?;
        let sequence = record.sequence;
        let event_id = record.event_id.clone();
        self.send_append(WriterCommand::Append {
            sequence,
            body: encode_bounded(&record)?,
        })?;
        cursor.next_sequence += 1;
        cursor.parent_event_id = Some(event_id);
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.barrier(false)
    }

    pub fn shutdown(&self, reason: impl Into<String>) -> Result<()> {
        if self.is_closed() {
            return Ok(());
        }
        self.record(SessionEvent::SessionEnd {
            reason: reason.into(),
        })?;
        self.barrier(true)
    }

    pub fn status(&self) -> SessionRecorderStatus {
        self.inner
            .status
            .lock()
            .expect("session recorder status poisoned")
            .clone()
    }

    fn send(&self, command: WriterCommand) -> Result<()> {
        let guard = self.inner.sender.lock().expect("session sender poisoned");
        let sender = guard.as_ref().context("session recorder is closed")?;
        sender.send(command).context("session writer stopped")
    }

    fn send_append(&self, command: WriterCommand) -> Result<()> {
        let guard = self.inner.sender.lock().expect("session sender poisoned");
        let sender = guard.as_ref().context("session recorder is closed")?;
        try_send_append(
            sender,
            command,
            &self.inner.status,
            &self.inner.event_budget,
        )
    }

    fn barrier(&self, shutdown: bool) -> Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let command = if shutdown {
            WriterCommand::Shutdown(sender)
        } else {
            WriterCommand::Flush(sender)
        };
        self.send(command)?;
        let result = receiver.recv().context("session writer stopped")?;
        if shutdown {
            self.inner
                .sender
                .lock()
                .expect("session sender poisoned")
                .take();
        }
        result.map_err(anyhow::Error::msg)
    }

    fn is_closed(&self) -> bool {
        self.inner
            .sender
            .lock()
            .expect("session sender poisoned")
            .is_none()
    }
}

impl Drop for RecorderInner {
    fn drop(&mut self) {
        let Some(sender) = self.sender.get_mut().ok().and_then(Option::take) else {
            return;
        };
        let (reply, _) = mpsc::sync_channel(1);
        let _ = sender.try_send(WriterCommand::Shutdown(reply));
    }
}

fn metadata_record(
    session_id: &str,
    event_id: &str,
    metadata: SessionMetadata,
) -> Result<SessionRecord> {
    Ok(SessionRecord {
        schema_version: super::SESSION_TRANSCRIPT_SCHEMA_VERSION,
        timestamp: super::time::now_timestamp(),
        session_id: session_id.to_string(),
        sequence: 0,
        event_id: event_id.to_string(),
        parent_event_id: None,
        event_type: "session_meta".to_string(),
        payload: metadata_payload(metadata)?,
    })
}

fn event_record(
    session_id: &str,
    cursor: &RecordCursor,
    event: SessionEvent,
) -> Result<SessionRecord> {
    let (event_type, payload) = event_parts(event)?;
    Ok(SessionRecord {
        schema_version: super::SESSION_TRANSCRIPT_SCHEMA_VERSION,
        timestamp: super::time::now_timestamp(),
        session_id: session_id.to_string(),
        sequence: cursor.next_sequence,
        event_id: Uuid::new_v4().to_string(),
        parent_event_id: cursor.parent_event_id.clone(),
        event_type,
        payload,
    })
}

fn initial_status(session_id: &str, path: &Path) -> Arc<Mutex<SessionRecorderStatus>> {
    Arc::new(Mutex::new(SessionRecorderStatus {
        session_id: session_id.to_string(),
        path: path.to_path_buf(),
        health: SessionRecorderHealth::Healthy,
        last_flushed_sequence: 0,
        pending_records: 0,
        last_error: None,
    }))
}

#[cfg(test)]
mod tests;
