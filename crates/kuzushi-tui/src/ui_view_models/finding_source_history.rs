//! Recorded observation boundaries, independent of confidence and decisions.
use kuzushi_core::findings::FindingSource;

const SOURCE_HISTORY_LIMIT: usize = 8;

pub(super) fn rows(sources: &[FindingSource]) -> Vec<String> {
    let mut rows = Vec::new();
    for source in sources.iter().take(SOURCE_HISTORY_LIMIT) {
        rows.push(format!("{} · {}", source.tool, source.source_signature));
        rows.push(observation(
            "First observation",
            &source.first_scan_id,
            &source.first_seen_at,
        ));
        rows.push(observation(
            "Latest observation",
            &source.last_scan_id,
            &source.last_seen_at,
        ));
    }
    if sources.len() > SOURCE_HISTORY_LIMIT {
        rows.push(format!(
            "{} more source histories; inspect the full export.",
            sources.len() - SOURCE_HISTORY_LIMIT
        ));
    }
    rows
}

fn observation(label: &str, run: &str, timestamp: &str) -> String {
    format!(
        "{label}: {run} · {}",
        super::recorded_timestamp_label(timestamp)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> FindingSource {
        FindingSource {
            tool: "owned".into(),
            vuln_source: None,
            source_signature: "note.md:1".into(),
            first_scan_id: "first-pass".into(),
            last_scan_id: "latest-pass".into(),
            first_seen_at: "1000".into(),
            last_seen_at: "2000".into(),
        }
    }

    #[test]
    fn observation_dates_remain_paired_with_their_run_ids() {
        let text = rows(&[source()]).join("\n");
        assert!(text.contains(&format!(
            "First observation: first-pass · {}",
            super::super::recorded_timestamp_label("1000")
        )));
        assert!(text.contains(&format!(
            "Latest observation: latest-pass · {}",
            super::super::recorded_timestamp_label("2000")
        )));
        assert!(!text.contains("confidence"));
    }

    #[test]
    fn source_history_is_bounded_and_missing_dates_stay_unknown() {
        let mut source = source();
        source.first_seen_at = "unknown".into();
        let rows = rows(&vec![source; SOURCE_HISTORY_LIMIT + 1]);
        assert_eq!(rows.len(), SOURCE_HISTORY_LIMIT * 3 + 1);
        assert!(rows[1].contains("unknown"));
        assert!(rows.last().unwrap().contains("1 more source histories"));
    }
}
