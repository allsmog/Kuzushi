//! Offline lints over recorded session transcripts.
//!
//! Transcripts are the only durable witness of what the shell actually did
//! at operator pace, so pathologies invisible in unit tests show up here:
//! a watcher re-announcing the same readiness line thousands of times, a
//! view change followed by a long silence, or a submitted command whose
//! first recorded response arrives seconds later. These lints fold a
//! session's records into findings an auditor can act on; they never judge
//! operator behavior, only what the shell recorded about itself.

use super::model::SessionRecord;

#[derive(Debug, Clone)]
pub struct SessionLintOptions {
    /// A `log_emitted` message repeated at least this many times inside any
    /// sixty-second window is a storm, not information.
    pub storm_repeats_per_minute: usize,
    /// Seconds of total record silence after a `view_changed` before the
    /// gap is worth an auditor's attention.
    pub view_change_silence_seconds: u64,
    /// Seconds between `command_submitted` and the next record of any kind
    /// before the shell's first response counts as slow.
    pub first_response_seconds: u64,
}

impl Default for SessionLintOptions {
    fn default() -> Self {
        Self {
            storm_repeats_per_minute: 30,
            view_change_silence_seconds: 60,
            first_response_seconds: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLintKind {
    RepeatedMessageStorm,
    SilentViewChange,
    SlowFirstResponse,
}

#[derive(Debug, Clone)]
pub struct SessionLintFinding {
    pub kind: SessionLintKind,
    /// Sequence of the record that anchors the finding.
    pub sequence: u64,
    pub timestamp: String,
    pub detail: String,
}

pub fn lint_session_records(
    records: &[SessionRecord],
    options: &SessionLintOptions,
) -> Vec<SessionLintFinding> {
    let mut findings = repeated_message_storms(records, options);
    findings.extend(silent_view_changes(records, options));
    findings.extend(slow_first_responses(records, options));
    findings.sort_by_key(|finding| finding.sequence);
    findings
}

struct MessageStream {
    anchor_sequence: u64,
    anchor_timestamp: String,
    times: Vec<u64>,
}

fn repeated_message_storms(
    records: &[SessionRecord],
    options: &SessionLintOptions,
) -> Vec<SessionLintFinding> {
    let mut streams = std::collections::BTreeMap::<(String, String), MessageStream>::new();
    for record in records {
        if record.event_type != "log_emitted" {
            continue;
        }
        let Some(millis) = record_millis(record) else {
            continue;
        };
        let level = payload_str(record, "level");
        let message = payload_str(record, "message");
        streams
            .entry((level, message))
            .or_insert_with(|| MessageStream {
                anchor_sequence: record.sequence,
                anchor_timestamp: record.timestamp.clone(),
                times: Vec::new(),
            })
            .times
            .push(millis);
    }
    storm_findings(streams, options.storm_repeats_per_minute)
}

fn storm_findings(
    streams: std::collections::BTreeMap<(String, String), MessageStream>,
    threshold: usize,
) -> Vec<SessionLintFinding> {
    let mut findings = Vec::new();
    for ((level, message), mut stream) in streams {
        stream.times.sort_unstable();
        let peak = peak_minute_count(&stream.times);
        if peak < threshold {
            continue;
        }
        findings.push(SessionLintFinding {
            kind: SessionLintKind::RepeatedMessageStorm,
            sequence: stream.anchor_sequence,
            timestamp: stream.anchor_timestamp,
            detail: format!(
                "[{level}] {message:?} recorded {} times ({peak}/min at peak) — \
                 a repeated announcement is a storm, not information",
                stream.times.len()
            ),
        });
    }
    findings
}

/// Largest number of occurrences inside any sliding sixty-second window.
fn peak_minute_count(sorted_times: &[u64]) -> usize {
    let mut peak = 0;
    let mut oldest = 0;
    for newest in 0..sorted_times.len() {
        while sorted_times[newest] - sorted_times[oldest] > 60_000 {
            oldest += 1;
        }
        peak = peak.max(newest - oldest + 1);
    }
    peak
}

fn silent_view_changes(
    records: &[SessionRecord],
    options: &SessionLintOptions,
) -> Vec<SessionLintFinding> {
    let mut findings = Vec::new();
    for pair in records.windows(2) {
        let (current, next) = (&pair[0], &pair[1]);
        if current.event_type != "view_changed" || next.event_type == "session_end" {
            continue;
        }
        let Some(gap_ms) = gap_between(current, next) else {
            continue;
        };
        if gap_ms <= options.view_change_silence_seconds * 1_000 {
            continue;
        }
        findings.push(SessionLintFinding {
            kind: SessionLintKind::SilentViewChange,
            sequence: current.sequence,
            timestamp: current.timestamp.clone(),
            detail: format!(
                "no session activity for {}s after switching to {:?}",
                gap_ms / 1_000,
                payload_str(current, "to"),
            ),
        });
    }
    findings
}

fn slow_first_responses(
    records: &[SessionRecord],
    options: &SessionLintOptions,
) -> Vec<SessionLintFinding> {
    let mut findings = Vec::new();
    for (index, record) in records.iter().enumerate() {
        if record.event_type != "command_submitted" {
            continue;
        }
        let command = payload_str(record, "command");
        if let Some(detail) = slow_response_detail(record, records.get(index + 1), options) {
            findings.push(SessionLintFinding {
                kind: SessionLintKind::SlowFirstResponse,
                sequence: record.sequence,
                timestamp: record.timestamp.clone(),
                detail: format!("{command:?}: {detail}"),
            });
        }
    }
    findings
}

fn slow_response_detail(
    command: &SessionRecord,
    next: Option<&SessionRecord>,
    options: &SessionLintOptions,
) -> Option<String> {
    let Some(next) = next else {
        return Some("no response was ever recorded".to_string());
    };
    let gap_ms = gap_between(command, next)?;
    if gap_ms <= options.first_response_seconds * 1_000 {
        return None;
    }
    Some(format!(
        "first recorded response ({}) arrived {:.1}s later",
        next.event_type,
        gap_ms as f64 / 1_000.0
    ))
}

fn gap_between(earlier: &SessionRecord, later: &SessionRecord) -> Option<u64> {
    let earlier = record_millis(earlier)?;
    let later = record_millis(later)?;
    Some(later.saturating_sub(earlier))
}

fn payload_str(record: &SessionRecord, key: &str) -> String {
    record
        .payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn record_millis(record: &SessionRecord) -> Option<u64> {
    parse_timestamp_millis(&record.timestamp)
}

/// Parses the recorder's own `YYYY-MM-DDTHH:MM:SS.mmmZ` timestamps back to
/// Unix milliseconds; the inverse of `time::timestamp_from_millis`.
fn parse_timestamp_millis(timestamp: &str) -> Option<u64> {
    let (date, time) = timestamp.split_once('T')?;
    let days = days_from_civil(parse_date(date)?)?;
    let (seconds_of_day, millis) = parse_time(time.strip_suffix('Z')?)?;
    Some(days * 86_400_000 + seconds_of_day * 1_000 + millis)
}

fn parse_date(date: &str) -> Option<(i64, i64, i64)> {
    let mut parts = date.splitn(3, '-');
    let year = parts.next()?.parse().ok()?;
    let month = parts.next()?.parse().ok()?;
    let day = parts.next()?.parse().ok()?;
    Some((year, month, day))
}

fn parse_time(time: &str) -> Option<(u64, u64)> {
    let (clock, millis) = match time.split_once('.') {
        Some((clock, fraction)) => (clock, parse_millis_fraction(fraction)?),
        None => (time, 0),
    };
    let mut parts = clock.splitn(3, ':');
    let hours: u64 = parts.next()?.parse().ok()?;
    let minutes: u64 = parts.next()?.parse().ok()?;
    let seconds: u64 = parts.next()?.parse().ok()?;
    Some((hours * 3_600 + minutes * 60 + seconds, millis))
}

fn parse_millis_fraction(fraction: &str) -> Option<u64> {
    let digits: String = fraction.chars().take(3).collect();
    let value: u64 = digits.parse().ok()?;
    Some(value * 10_u64.pow(3_u32.saturating_sub(digits.len() as u32)))
}

/// Days since the Unix epoch for a civil date, rejecting pre-epoch dates.
fn days_from_civil((year, month, day): (i64, i64, i64)) -> Option<u64> {
    let shifted_year = year - i64::from(month <= 2);
    let era = if shifted_year >= 0 {
        shifted_year
    } else {
        shifted_year - 399
    } / 400;
    let year_of_era = shifted_year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    u64::try_from(era * 146_097 + day_of_era - 719_468).ok()
}

#[cfg(test)]
mod tests;
