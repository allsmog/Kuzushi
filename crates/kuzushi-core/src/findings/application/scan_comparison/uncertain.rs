//! Same tool/rule/file/title with a different identity: flagged, never
//! silently classified as resolved-plus-new.

use super::{ScanFindingSignature, ScanUncertainMatch};
use crate::findings::Finding;
use std::collections::BTreeMap;

pub(super) fn uncertain_matches(
    base: &BTreeMap<String, Finding>,
    compare: &BTreeMap<String, Finding>,
) -> Vec<ScanUncertainMatch> {
    let base_candidates = unmatched_by_match_key(base, compare);
    let compare_candidates = unmatched_by_match_key(compare, base);
    base_candidates
        .iter()
        .filter_map(|(match_key, base_rows)| {
            uncertain_match_row(base_rows, compare_candidates.get(match_key)?)
        })
        .collect()
}

fn unmatched_by_match_key<'a>(
    source: &'a BTreeMap<String, Finding>,
    other: &BTreeMap<String, Finding>,
) -> BTreeMap<String, Vec<(&'a String, &'a Finding)>> {
    let mut grouped = BTreeMap::<String, Vec<(&String, &Finding)>>::new();
    for (key, finding) in source.iter().filter(|(key, _)| !other.contains_key(*key)) {
        grouped
            .entry(finding_match_key(finding))
            .or_default()
            .push((key, finding));
    }
    grouped
}

fn uncertain_match_row(
    base_rows: &[(&String, &Finding)],
    compare_rows: &[(&String, &Finding)],
) -> Option<ScanUncertainMatch> {
    let ([(base_key, base)], [(compare_key, compare)]) = (base_rows, compare_rows) else {
        return None;
    };
    Some(ScanUncertainMatch {
        base_key: (*base_key).clone(),
        compare_key: (*compare_key).clone(),
        title: base.title.clone(),
        before: ScanFindingSignature::of(base),
        after: ScanFindingSignature::of(compare),
        reason: "same tool/rule/file/title but different identity or fingerprint; review before carrying decisions".to_string(),
    })
}

fn finding_match_key(finding: &Finding) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        normalize_match_token(&finding.tool),
        normalize_match_token(&finding.rule_id),
        normalize_match_token(&finding.file_path.replace('\\', "/")),
        normalize_match_token(&finding.title),
    )
}

fn normalize_match_token(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}
