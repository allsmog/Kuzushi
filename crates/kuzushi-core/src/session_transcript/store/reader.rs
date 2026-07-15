use super::super::model::*;
use super::super::process_identity::{self, ProcessLiveness};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) fn parse_records(body: &str) -> (Vec<SessionRecord>, Vec<String>) {
    let mut records = Vec::new();
    let mut warnings = Vec::new();
    for (index, line) in body.split_inclusive('\n').enumerate() {
        if !line.ends_with('\n') {
            warnings.push(format!("line {} is incomplete and was skipped", index + 1));
            continue;
        }
        parse_record_line(
            line.trim_end_matches('\n'),
            index + 1,
            &mut records,
            &mut warnings,
        );
    }
    add_sequence_warnings(&records, &mut warnings);
    (records, warnings)
}

pub(super) fn summarize(
    path: &Path,
    records: &[SessionRecord],
    parse_warning_count: usize,
) -> Result<SessionSummary> {
    let first = records
        .first()
        .context("session transcript has no readable records")?;
    anyhow::ensure!(
        first.event_type == "session_meta",
        "first session record is not session_meta"
    );
    let metadata: SessionMetadata = serde_json::from_value(first.payload.clone())
        .context("session metadata has an invalid schema")?;
    validate_record_chain(records, &first.session_id)?;
    let current_target = current_target(records, metadata.initial_target.clone());
    let ended_at = session_end_timestamp(records);
    let status = session_status(ended_at.is_some(), &metadata);
    Ok(SessionSummary {
        session_id: first.session_id.clone(),
        path: path.to_path_buf(),
        started_at: first.timestamp.clone(),
        ended_at,
        status,
        process_id: metadata.process_id,
        shell_mode: metadata.shell_mode,
        initial_target: metadata.initial_target,
        current_target,
        event_count: records.len(),
        warning_count: parse_warning_count + session_warning_count(records),
    })
}

pub(super) fn read_matches_target(read: &SessionReadResult, target: Option<&Path>) -> bool {
    let Some(target) = target else {
        return true;
    };
    read.summary
        .initial_target
        .as_deref()
        .is_some_and(|value| same_path(value, target))
        || read
            .records
            .iter()
            .any(|record| record_matches_target(record, target))
}

fn parse_record_line(
    line: &str,
    line_number: usize,
    records: &mut Vec<SessionRecord>,
    warnings: &mut Vec<String>,
) {
    if line.len() > super::super::MAX_SESSION_RECORD_BYTES {
        warnings.push(format!("line {line_number} exceeds the record limit"));
        return;
    }
    let record = match serde_json::from_str::<SessionRecord>(line) {
        Ok(record) => record,
        Err(error) => {
            warnings.push(format!("line {line_number} is invalid JSON: {error}"));
            return;
        }
    };
    if record.schema_version != super::super::SESSION_TRANSCRIPT_SCHEMA_VERSION {
        warnings.push(format!(
            "line {line_number} has an unsupported schema version"
        ));
        return;
    }
    records.push(record);
}

fn add_sequence_warnings(records: &[SessionRecord], warnings: &mut Vec<String>) {
    for pair in records.windows(2) {
        if pair[1].sequence > pair[0].sequence + 1 {
            warnings.push(format!(
                "records {} and {} have a sequence gap",
                pair[0].sequence, pair[1].sequence
            ));
        }
    }
}

fn validate_record_chain(records: &[SessionRecord], session_id: &str) -> Result<()> {
    for record in records {
        anyhow::ensure!(
            record.session_id == session_id,
            "session transcript contains mixed session ids"
        );
    }
    for pair in records.windows(2) {
        anyhow::ensure!(
            pair[1].sequence > pair[0].sequence,
            "session transcript sequence is not monotonic"
        );
    }
    Ok(())
}

fn current_target(records: &[SessionRecord], initial: Option<PathBuf>) -> Option<PathBuf> {
    records.iter().fold(initial, |target, record| {
        match record.event_type.as_str() {
            "target_activated" => activated_target(record).or(target),
            "target_cleared" => None,
            _ => target,
        }
    })
}

fn activated_target(record: &SessionRecord) -> Option<PathBuf> {
    record
        .payload
        .get("target")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
}

fn session_end_timestamp(records: &[SessionRecord]) -> Option<String> {
    records
        .iter()
        .rev()
        .find(|record| record.event_type == "session_end")
        .map(|record| record.timestamp.clone())
}

fn session_status(ended: bool, metadata: &SessionMetadata) -> SessionStatus {
    if ended {
        return SessionStatus::Completed;
    }
    match process_identity::liveness(metadata.process_id, metadata.process_start_token.as_deref()) {
        ProcessLiveness::Alive => SessionStatus::Running,
        ProcessLiveness::Dead => SessionStatus::Interrupted,
        ProcessLiveness::Unknown => SessionStatus::Unknown,
    }
}

fn session_warning_count(records: &[SessionRecord]) -> usize {
    records
        .iter()
        .filter(|record| record.event_type == "session_warning")
        .count()
}

fn record_matches_target(record: &SessionRecord, target: &Path) -> bool {
    record.event_type == "target_activated"
        && record
            .payload
            .get("target")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| same_path(Path::new(value), target))
}

fn same_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}
