//! Shared recorded observation presentation for case results and Report.
use kuzushi_core::findings::BatchOccurrenceRow;
use serde_json::Value;

pub(super) fn append_observation_summary(
    lines: &mut Vec<String>,
    row: &BatchOccurrenceRow,
    completed: usize,
) {
    lines.extend([
        format!(
            "observed {} / {completed} · {} · {}",
            row.seen, row.representative_severity, row.representative_title
        ),
        format!(
            "Location: {}",
            Value::String(row.representative_location.clone())
        ),
    ]);
}

pub(super) fn append_observation_receipt(lines: &mut Vec<String>, row: &BatchOccurrenceRow) {
    lines.extend([
        format!(
            "Observation receipt: {}",
            Value::String(row.representative_location.clone())
        ),
        format!("Fingerprint: {}", row.representative_fingerprint),
    ]);
    if let Some(identity) = &row.identity_id {
        lines.push(format!("Identity: {identity}"));
    }
    for location in row
        .locations
        .iter()
        .filter(|location| *location != &row.representative_location)
    {
        lines.push(format!(
            "Recorded location: {}",
            Value::String(location.clone())
        ));
    }
    for run in &row.run_ids {
        lines.push(format!("Run: {run}"));
    }
}
