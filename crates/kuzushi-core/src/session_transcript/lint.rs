//! Deterministic session-transcript lint. No model calls: the same
//! transcript always yields the same report. Feeds the fidelity scorecard —
//! this is how the watcher-storm bug was found by hand, mechanized.

use super::model::{SessionEvent, SessionRecord};
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TranscriptLintReport {
    pub events: usize,
    /// Longest run of identical consecutive log messages — the spam /
    /// watcher-storm signal.
    pub max_repeated_log_run: usize,
    pub repeated_log_message: Option<String>,
    /// Longest silent gap between consecutive events, in seconds.
    pub max_stall_seconds: i64,
    /// Runs that started but never finished in this transcript.
    pub unfinished_runs: Vec<String>,
    pub warnings: usize,
}

impl TranscriptLintReport {
    /// Conservative fidelity gate: spammy or stalled sessions need a look.
    pub fn suspicious(&self) -> bool {
        self.max_repeated_log_run >= 20
            || self.max_stall_seconds >= 1800
            || !self.unfinished_runs.is_empty()
    }
}

pub fn lint_transcript(records: &[SessionRecord]) -> TranscriptLintReport {
    TranscriptLintReport {
        events: records.len(),
        max_repeated_log_run: repeated_log_run(records).0,
        repeated_log_message: repeated_log_run(records).1,
        max_stall_seconds: max_stall_seconds(records),
        unfinished_runs: unfinished_runs(records),
        warnings: warning_count(records),
    }
}

fn repeated_log_run(records: &[SessionRecord]) -> (usize, Option<String>) {
    let mut best = (0usize, None);
    let mut current: Option<(String, usize)> = None;
    for record in records {
        let Some(SessionEvent::LogEmitted { message, .. }) = event_of(record) else {
            current = None;
            continue;
        };
        current = Some(match current {
            Some((last, count)) if last == message => (last, count + 1),
            _ => (message, 1),
        });
        let (message, count) = current.as_ref().expect("just set");
        if *count > best.0 {
            best = (*count, Some(message.clone()));
        }
    }
    best
}

/// Records store the event as (`type`, `payload`); rebuild the typed enum
/// and skip rows a newer writer emitted with kinds this reader predates.
fn event_of(record: &SessionRecord) -> Option<SessionEvent> {
    serde_json::from_value(json!({ "type": record.event_type, "data": record.payload })).ok()
}

fn max_stall_seconds(records: &[SessionRecord]) -> i64 {
    records
        .windows(2)
        .filter_map(|pair| {
            let earlier = parse_unixish(&pair[0].timestamp)?;
            let later = parse_unixish(&pair[1].timestamp)?;
            Some(later - earlier)
        })
        .max()
        .unwrap_or(0)
}

/// Timestamps are RFC3339-ish; second-resolution ordering is all the lint
/// needs, so parse conservatively and skip rows that don't parse.
fn parse_unixish(timestamp: &str) -> Option<i64> {
    let normalized = timestamp.trim().replace('T', " ");
    let (date, time) = normalized.split_once(' ')?;
    let days = civil_days(date)?;
    let mut clock = time.trim_end_matches('Z').splitn(3, ':');
    let hours: i64 = clock.next()?.parse().ok()?;
    let minutes: i64 = clock.next()?.parse().ok()?;
    let seconds: i64 = clock.next()?.split('.').next()?.parse().ok()?;
    Some(days * 86_400 + hours * 3_600 + minutes * 60 + seconds)
}

fn civil_days(date: &str) -> Option<i64> {
    let mut parts = date.splitn(3, '-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    // Howard Hinnant's days-from-civil; exact for the Gregorian calendar.
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

fn unfinished_runs(records: &[SessionRecord]) -> Vec<String> {
    let mut open = Vec::new();
    for record in records {
        match event_of(record) {
            Some(SessionEvent::RunStarted { run_id, .. }) => open.push(run_id),
            Some(SessionEvent::RunFinished { run_id, .. }) => open.retain(|id| *id != run_id),
            _ => {}
        }
    }
    open
}

fn warning_count(records: &[SessionRecord]) -> usize {
    records
        .iter()
        .filter(|record| {
            matches!(event_of(record), Some(SessionEvent::SessionWarning { .. }))
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(timestamp: &str, event: SessionEvent) -> SessionRecord {
        let serialized = serde_json::to_value(&event).unwrap();
        SessionRecord {
            schema_version: 1,
            timestamp: timestamp.to_string(),
            session_id: "session-1".to_string(),
            sequence: 0,
            event_id: "event-1".to_string(),
            parent_event_id: None,
            event_type: serialized["type"].as_str().unwrap().to_string(),
            payload: serialized["data"].clone(),
        }
    }

    fn log(timestamp: &str, message: &str) -> SessionRecord {
        record(
            timestamp,
            SessionEvent::LogEmitted {
                level: "info".to_string(),
                message: message.to_string(),
            },
        )
    }

    #[test]
    fn repeated_log_spam_and_stalls_are_measured() {
        let mut records = vec![log("2026-07-20T10:00:00Z", "watching workspace")];
        for _ in 0..25 {
            records.push(log("2026-07-20T10:00:01Z", "workspace changed; reloading"));
        }
        records.push(log("2026-07-20T11:00:01Z", "done"));

        let report = lint_transcript(&records);

        assert_eq!(report.max_repeated_log_run, 25);
        assert_eq!(
            report.repeated_log_message.as_deref(),
            Some("workspace changed; reloading")
        );
        assert_eq!(report.max_stall_seconds, 3600);
        assert!(report.suspicious());
    }

    #[test]
    fn balanced_runs_and_quiet_logs_are_not_suspicious() {
        let records = vec![
            record(
                "2026-07-20T10:00:00Z",
                SessionEvent::RunStarted {
                    run_id: "run-1".to_string(),
                    tool_name: "sast:scan".to_string(),
                },
            ),
            record(
                "2026-07-20T10:05:00Z",
                SessionEvent::RunFinished {
                    run_id: "run-1".to_string(),
                    tool_name: "sast:scan".to_string(),
                    status: "completed".to_string(),
                },
            ),
        ];

        let report = lint_transcript(&records);

        assert!(report.unfinished_runs.is_empty());
        assert!(!report.suspicious());
    }

    #[test]
    fn a_run_that_never_finishes_is_flagged() {
        let records = vec![record(
            "2026-07-20T10:00:00Z",
            SessionEvent::RunStarted {
                run_id: "run-9".to_string(),
                tool_name: "verify:finding".to_string(),
            },
        )];

        let report = lint_transcript(&records);

        assert_eq!(report.unfinished_runs, vec!["run-9".to_string()]);
        assert!(report.suspicious());
    }
}
