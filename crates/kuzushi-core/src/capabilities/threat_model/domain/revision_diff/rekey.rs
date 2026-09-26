//! Pairing for threats a key match missed. Independent builds mint fresh
//! `stableId`s for the same modeled threat, so threats unmatched on both sides
//! pair by a display `id` that names exactly one threat on each side.

use super::{non_empty_text, threat_change, unmatched_rows, KeyedThreats, ThreatFieldChange};
use serde_json::Value;
use std::collections::BTreeMap;

/// A threat unmatched by key on both sides, paired by its display `id`.
pub(super) struct ThreatRekey<'a> {
    pub(super) from_key: String,
    pub(super) to_key: String,
    before: &'a Value,
    after: &'a Value,
}

impl ThreatRekey<'_> {
    pub(super) fn change(&self) -> Option<ThreatFieldChange> {
        threat_change(&self.to_key, self.before, self.after)
    }
}

pub(super) fn display_id_rekeys<'a>(
    before: &KeyedThreats<'a>,
    after: &KeyedThreats<'a>,
) -> Vec<ThreatRekey<'a>> {
    let unmatched_before = unmatched_by_unique_display_id(before, after);
    let mut unmatched_after = unmatched_by_unique_display_id(after, before);
    unmatched_before
        .into_iter()
        .filter_map(|(id, (from_key, threat))| {
            let (to_key, paired) = unmatched_after.remove(&id)?;
            Some(ThreatRekey { from_key, to_key, before: threat, after: paired })
        })
        .collect()
}

/// Unmatched threats by display `id`, keeping only ids that name exactly one
/// threat on this side: a shared id cannot pair threats unambiguously.
fn unmatched_by_unique_display_id<'a>(
    source: &KeyedThreats<'a>,
    other: &KeyedThreats<'a>,
) -> BTreeMap<String, (String, &'a Value)> {
    let mut id_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (_, threat) in &source.rows {
        if let Some(id) = non_empty_text(threat, "id") {
            *id_counts.entry(id).or_default() += 1;
        }
    }
    unmatched_rows(source, other)
        .filter_map(|(key, threat)| Some((non_empty_text(threat, "id")?, (key.clone(), *threat))))
        .filter(|(id, _)| id_counts.get(id) == Some(&1))
        .collect()
}
