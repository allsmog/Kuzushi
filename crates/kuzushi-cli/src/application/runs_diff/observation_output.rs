//! Neutral comparison labels shared by plain and structured CLI output.
use kuzushi_core::findings::{ScanObservationPresence, ScanRunComparison};
use serde_json::{json, Value};

pub(super) fn count(comparison: &ScanRunComparison, presence: ScanObservationPresence) -> usize {
    comparison
        .findings
        .iter()
        .filter(|row| row.observation_presence() == presence)
        .count()
}

pub(super) fn counts_json(comparison: &ScanRunComparison) -> Value {
    use ScanObservationPresence::*;
    json!({
        "newlyObserved": count(comparison, NewlyObserved),
        "seenAgain": count(comparison, SeenAgain),
        "notObserved": count(comparison, NotObserved),
        "notReassessed": count(comparison, NotReassessed),
        "unknown": count(comparison, Unknown),
    })
}

pub(super) fn presence_json(comparison: &ScanRunComparison) -> Vec<Value> {
    comparison
        .findings
        .iter()
        .map(|row| {
            json!({
                "findingKey": row.stable_key, "title": row.title,
                "file": row.file_path, "tool": row.tool,
                "status": row.observation_presence().as_str(),
                "reason": row.reassessment_block, "fixStatus": "not_assessed",
            })
        })
        .collect()
}

pub(super) fn counts_label(comparison: &ScanRunComparison) -> String {
    use ScanObservationPresence::*;
    format!(
        "newly_observed={} seen_again={} not_observed={} not_reassessed={} unknown={}",
        count(comparison, NewlyObserved),
        count(comparison, SeenAgain),
        count(comparison, NotObserved),
        count(comparison, NotReassessed),
        count(comparison, Unknown)
    )
}

pub(super) fn append_presence(lines: &mut Vec<String>, comparison: &ScanRunComparison) {
    use ScanObservationPresence::*;
    for (presence, label) in [
        (NewlyObserved, "Newly observed"),
        (SeenAgain, "Seen again"),
        (NotObserved, "Not observed in covered work"),
        (NotReassessed, "Not reassessed"),
        (Unknown, "Presence unknown"),
    ] {
        append_presence_group(lines, comparison, presence, label);
    }
}

fn append_presence_group(
    lines: &mut Vec<String>,
    comparison: &ScanRunComparison,
    presence: ScanObservationPresence,
    label: &str,
) {
    let mut rows = comparison
        .findings
        .iter()
        .filter(|row| row.observation_presence() == presence)
        .peekable();
    if rows.peek().is_none() {
        return;
    }
    lines.push(format!("{label}:"));
    for row in rows {
        lines.push(format!(
            "  {} · {} · {}",
            row.title, row.file_path, row.stable_key
        ));
        if let Some(reason) = &row.reassessment_block {
            lines.push(format!("  Coverage: {reason}"));
        }
    }
}
