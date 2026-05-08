use super::prelude::*;
use super::*;

pub fn match_static_registry(query: &StaticRegistryQuery<'_>) -> Vec<StaticRegistryMatch> {
    DEFAULT_STATIC_REGISTRY
        .iter()
        .filter(|entry| entry_matches_query(entry, query))
        .map(|entry| StaticRegistryMatch {
            entry,
            static_proof_state: StaticProofState::SignalOnly,
            vulnerability_proof: false,
        })
        .collect()
}

pub(crate) fn entry_matches_query(
    entry: &StaticRegistryEntry,
    query: &StaticRegistryQuery<'_>,
) -> bool {
    if !eq_ignore_ascii_case(entry.language, query.language) {
        return false;
    }

    if let Some(framework) = entry.framework {
        let Some(query_framework) = query.framework else {
            return false;
        };
        if !eq_ignore_ascii_case(framework, query_framework) {
            return false;
        }
    }

    match entry.pattern_kind {
        StaticRegistryPatternKind::SymbolEquals => query
            .symbol
            .is_some_and(|symbol| eq_ignore_ascii_case(symbol, entry.pattern)),
        StaticRegistryPatternKind::SymbolContains => query.symbol.is_some_and(|symbol| {
            contains_ignore_ascii_case(symbol, entry.pattern)
                || query
                    .text
                    .is_some_and(|text| contains_ignore_ascii_case(text, entry.pattern))
        }),
        StaticRegistryPatternKind::PathContains => query
            .path
            .is_some_and(|path| contains_ignore_ascii_case(path, entry.pattern)),
        StaticRegistryPatternKind::TextContains => query
            .text
            .is_some_and(|text| contains_ignore_ascii_case(text, entry.pattern)),
    }
}

pub(crate) fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

pub(crate) fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}
