//! Source histories follow authoritative observation order, not confidence.
use super::FindingSource;
use std::collections::BTreeMap;

pub(crate) fn merge_ordered_source_histories(
    earlier: &[FindingSource],
    later: &[FindingSource],
) -> Vec<FindingSource> {
    let mut merged = BTreeMap::new();
    for source in earlier.iter().chain(later) {
        let key = (source.tool.clone(), source.source_signature.clone());
        merged
            .entry(key)
            .and_modify(|existing| update_latest(existing, source))
            .or_insert_with(|| source.clone());
    }
    merged.into_values().collect()
}

fn update_latest(existing: &mut FindingSource, later: &FindingSource) {
    if existing.vuln_source.is_none() {
        existing.vuln_source = later.vuln_source;
    }
    existing.last_scan_id = later.last_scan_id.clone();
    existing.last_seen_at = later.last_seen_at.clone();
}

pub fn distinct_recorded_source_count(sources: &[FindingSource]) -> usize {
    sources
        .iter()
        .map(|source| (&source.tool, &source.source_signature))
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(run: &str) -> FindingSource {
        FindingSource {
            tool: "owned".into(),
            vuln_source: None,
            source_signature: "note.md:1".into(),
            first_scan_id: run.into(),
            last_scan_id: run.into(),
            first_seen_at: "unknown".into(),
            last_seen_at: "unknown".into(),
        }
    }

    #[test]
    fn repeat_observations_preserve_boundary_runs_and_count_one_source() {
        let first = source("run-z");
        let later = source("run-a");
        let merged = merge_ordered_source_histories(&[first.clone()], &[later.clone()]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].first_scan_id, "run-z");
        assert_eq!(merged[0].last_scan_id, "run-a");
        assert_eq!(merged[0].first_seen_at, "unknown");
        assert_eq!(distinct_recorded_source_count(&[first, later]), 1);
    }

    #[test]
    fn other_producers_or_source_signatures_remain_distinct() {
        let first = source("one");
        let mut other = source("two");
        other.tool = "other".into();
        let mut different = source("three");
        different.source_signature = "other.md:1".into();
        let merged = merge_ordered_source_histories(&[first], &[other, different]);
        assert_eq!(merged.len(), 3);
        assert_eq!(distinct_recorded_source_count(&merged), 3);
    }
}
