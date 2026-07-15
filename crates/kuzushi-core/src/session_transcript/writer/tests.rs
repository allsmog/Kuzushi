use super::background::{try_send_append, WriterState};
use super::budget::OutstandingEventBudget;
use super::file_io::write_pending_once;
use super::*;
use std::io::Write;

struct PartialThenFailWriter {
    output: Vec<u8>,
    calls: usize,
}

impl Write for PartialThenFailWriter {
    fn write(&mut self, body: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        if self.calls == 2 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "injected"));
        }
        let count = if self.calls == 1 {
            body.len().min(3)
        } else {
            body.len()
        };
        self.output.extend_from_slice(&body[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn retry_resumes_at_the_unwritten_suffix_after_a_partial_write() {
    let body = b"complete-json-line\n";
    let mut offset = 0;
    let mut writer = PartialThenFailWriter {
        output: Vec::new(),
        calls: 0,
    };

    assert!(!write_pending_once(&mut writer, body, &mut offset).unwrap());
    assert!(write_pending_once(&mut writer, body, &mut offset).is_err());
    assert!(!write_pending_once(&mut writer, body, &mut offset).unwrap());
    assert!(write_pending_once(&mut writer, body, &mut offset).unwrap());
    assert_eq!(writer.output, body);
}

#[test]
fn queue_pressure_is_nonblocking_and_marks_the_recorder_degraded() {
    let (sender, _receiver) = mpsc::sync_channel(1);
    let status = initial_status("session", Path::new("session.jsonl"));
    let event_budget = Arc::new(OutstandingEventBudget::new(WRITER_QUEUE_CAPACITY));
    let command = || WriterCommand::Append {
        sequence: 1,
        body: b"{}\n".to_vec(),
    };
    sender.try_send(command()).unwrap();

    let error = try_send_append(&sender, command(), &status, &event_budget).unwrap_err();
    assert!(error.to_string().contains("queue is full"));
    let status = status.lock().unwrap();
    assert_eq!(status.health, SessionRecorderHealth::Warning);
    assert_eq!(
        status.last_error.as_deref(),
        Some("session transcript queue is full")
    );
}

#[test]
fn successful_retry_restores_healthy_status() {
    let temp = tempfile::tempfile().unwrap();
    let status = initial_status("session", Path::new("session.jsonl"));
    {
        let mut current = status.lock().unwrap();
        current.health = SessionRecorderHealth::Warning;
        current.last_error = Some("transient failure".to_string());
    }
    let event_budget = Arc::new(OutstandingEventBudget::new(WRITER_QUEUE_CAPACITY));
    let state = WriterState::new(
        PathBuf::from("session.jsonl"),
        temp,
        Arc::clone(&status),
        event_budget,
    );

    state.note_recovered();

    let status = status.lock().unwrap();
    assert_eq!(status.health, SessionRecorderHealth::Healthy);
    assert_eq!(status.last_error, None);
}

#[test]
fn persistent_failure_retains_at_most_the_shared_event_budget() {
    let temp = tempfile::tempdir().unwrap();
    let readable = temp.path().join("read-only-source");
    std::fs::write(&readable, b"existing").unwrap();
    let read_only_file = std::fs::File::open(readable).unwrap();
    let missing_destination = temp.path().join("missing/session.jsonl");
    let status = initial_status("session", &missing_destination);
    let event_budget = Arc::new(OutstandingEventBudget::new(WRITER_QUEUE_CAPACITY));
    let mut state = WriterState::new(
        missing_destination,
        read_only_file,
        Arc::clone(&status),
        Arc::clone(&event_budget),
    );

    for sequence in 1..=WRITER_QUEUE_CAPACITY as u64 {
        assert!(event_budget.try_reserve());
        state.queue(sequence, b"{}\n".to_vec());
        assert!(state.drain_with_retry().is_err());
    }

    let (sender, _receiver) = mpsc::sync_channel(1);
    let overflow = WriterCommand::Append {
        sequence: WRITER_QUEUE_CAPACITY as u64 + 1,
        body: b"{}\n".to_vec(),
    };
    let error = try_send_append(&sender, overflow, &status, &event_budget).unwrap_err();

    assert!(error.to_string().contains("queue is full"));
    assert_eq!(state.pending_len(), WRITER_QUEUE_CAPACITY);
    assert_eq!(event_budget.pending(), WRITER_QUEUE_CAPACITY);
    let status = status.lock().unwrap();
    assert_eq!(status.pending_records, WRITER_QUEUE_CAPACITY);
    assert_eq!(status.health, SessionRecorderHealth::Warning);
}
