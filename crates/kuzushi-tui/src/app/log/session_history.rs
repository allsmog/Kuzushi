//! Reads the durable session transcript back into log rows.
//!
//! The live log cache holds only the most recent lines. Everything older was
//! already written to `~/.kuzushi/v3/sessions/`, so the Logs view pages into
//! that file rather than reporting the earlier output as lost.

use crate::LogLine;
use kuzushi_core::session_transcript::{
    unix_seconds_from_timestamp, SessionRecord, SessionTranscriptStore,
};
use std::path::{Path, PathBuf};

/// Earlier rows recovered from the durable transcript, kept beside the reason
/// they could not be recovered so the view never implies a silent gap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionHistory {
    lines: Vec<LogLine>,
    source: Option<PathBuf>,
    error: Option<String>,
}

impl SessionHistory {
    pub(crate) fn load(path: &Path) -> Self {
        match SessionTranscriptStore::read_file(path) {
            Ok(read) => Self {
                lines: project_records(&read.records),
                source: Some(read.path),
                error: None,
            },
            Err(error) => Self {
                lines: Vec::new(),
                source: Some(path.to_path_buf()),
                error: Some(error.to_string()),
            },
        }
    }

    pub(crate) fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn from_lines_for_test(lines: Vec<LogLine>) -> Self {
        Self {
            lines,
            source: None,
            error: None,
        }
    }

    /// The rows that precede the live cache. The transcript also contains the
    /// lines still held in memory, so the tail is dropped to avoid repeating
    /// them beneath the same header.
    pub(crate) fn lines_before_live(&self, live_len: usize) -> &[LogLine] {
        let keep = self.lines.len().saturating_sub(live_len);
        &self.lines[..keep]
    }
}

/// Projects durable records onto the operator's log vocabulary. Only the two
/// event types that produced visible rows are replayed; structural events
/// (view changes, run boundaries) already surfaced as their own log lines.
fn project_records(records: &[SessionRecord]) -> Vec<LogLine> {
    records.iter().filter_map(project_record).collect()
}

fn project_record(record: &SessionRecord) -> Option<LogLine> {
    let (prefix, body) = match record.event_type.as_str() {
        "log_emitted" => (
            field(record, "level").unwrap_or_else(|| "log".to_string()),
            field(record, "message")?,
        ),
        "command_submitted" => (">".to_string(), field(record, "command")?),
        _ => return None,
    };
    Some(LogLine {
        prefix,
        body,
        time_secs: unix_seconds_from_timestamp(&record.timestamp).unwrap_or_default(),
    })
}

fn field(record: &SessionRecord, key: &str) -> Option<String> {
    record
        .payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(event_type: &str, payload: serde_json::Value) -> SessionRecord {
        SessionRecord {
            schema_version: 1,
            timestamp: "2026-07-28T01:02:03.000Z".to_string(),
            session_id: "session".to_string(),
            sequence: 1,
            event_id: "event".to_string(),
            parent_event_id: None,
            event_type: event_type.to_string(),
            payload,
        }
    }

    #[test]
    fn replays_logged_lines_and_operator_commands_in_order() {
        let records = vec![
            record("command_submitted", json!({"command": "scan ."})),
            record(
                "log_emitted",
                json!({"level": "tool", "message": "running"}),
            ),
            record("view_changed", json!({"to": "workbench"})),
            record(
                "log_emitted",
                json!({"level": "error", "message": "failed"}),
            ),
        ];

        let lines = project_records(&records);

        let rendered = lines
            .iter()
            .map(|line| (line.prefix.as_str(), line.body.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            [(">", "scan ."), ("tool", "running"), ("error", "failed"),]
        );
    }

    #[test]
    fn dates_replayed_rows_from_the_recorded_stamp() {
        let lines = project_records(&[record(
            "log_emitted",
            json!({"level": "tool", "message": "running"}),
        )]);

        assert_eq!(lines[0].time_secs, 1_785_200_523);
    }

    #[test]
    fn skips_records_missing_the_body_they_would_render() {
        let records = vec![
            record("log_emitted", json!({"level": "tool"})),
            record("command_submitted", json!({})),
        ];

        assert!(project_records(&records).is_empty());
    }

    #[test]
    fn drops_the_tail_already_held_in_the_live_cache() {
        let history = SessionHistory {
            lines: vec![
                LogLine::new("tool", "one"),
                LogLine::new("tool", "two"),
                LogLine::new("tool", "three"),
            ],
            source: None,
            error: None,
        };

        let earlier = history
            .lines_before_live(2)
            .iter()
            .map(|line| line.body.as_str())
            .collect::<Vec<_>>();

        assert_eq!(earlier, ["one"]);
    }

    /// Round-trips the real recorder: what the shell writes during a session is
    /// what the Logs view reads back, including the `>` operator echo that the
    /// live cache records separately from `LogEmitted`.
    #[test]
    fn reads_back_a_transcript_written_by_the_real_recorder() {
        use kuzushi_core::session_transcript::{
            SessionEvent, SessionMetadata, SessionTranscriptStore,
        };

        let root = tempfile::tempdir().expect("sessions root");
        let store = SessionTranscriptStore::from_root(root.path());
        let recorder = store
            .start(SessionMetadata::new("interactive", root.path()))
            .expect("start session");
        recorder
            .record(SessionEvent::CommandSubmitted {
                command: "scan .".to_string(),
            })
            .expect("record command");
        recorder
            .record(SessionEvent::LogEmitted {
                level: "tool".to_string(),
                message: "running semgrep".to_string(),
            })
            .expect("record log");
        recorder
            .record(SessionEvent::ViewChanged {
                from: None,
                to: "workbench".to_string(),
            })
            .expect("record view");
        recorder.flush().expect("flush");

        let history = SessionHistory::load(recorder.path());

        assert_eq!(history.error(), None);
        let rendered = history
            .lines
            .iter()
            .map(|line| (line.prefix.as_str(), line.body.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(rendered, [(">", "scan ."), ("tool", "running semgrep")]);
        assert!(history.lines[0].time_secs > 0, "rows carry their timestamp");
    }

    #[test]
    fn reports_an_unreadable_transcript_instead_of_an_empty_history() {
        let history = SessionHistory::load(Path::new("/nonexistent/session.jsonl"));

        assert!(history.lines.is_empty());
        assert!(history.error().is_some());
    }
}
