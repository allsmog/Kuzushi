use super::*;
use crate::text::truncate::utf8_prefix;

pub(crate) fn group_registry_by_kind(
    matches: &[StaticRegistryMatch],
) -> std::collections::BTreeMap<StaticRegistryKind, Vec<&StaticRegistryMatch>> {
    let mut out: std::collections::BTreeMap<StaticRegistryKind, Vec<&StaticRegistryMatch>> =
        std::collections::BTreeMap::new();
    for m in matches {
        out.entry(m.entry.kind).or_default().push(m);
    }
    out
}

pub(crate) fn truncate_for_prompt(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    format!("{}...", utf8_prefix(s, max))
}
