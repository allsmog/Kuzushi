//! Variant patterns on the active threat model (confirmed findings that
//! refine compacted onto their threats) seed the matching CWE's structural
//! queries, so the next hunt searches for siblings of the proven call site.
//! The pattern CWE itself already earns the threat-model rank bonus because
//! `collect_taint_iris_next_cwes` walks the whole document.

use super::*;

const MAX_SEEDED_KEYWORDS_PER_ENTRY: usize = 12;
/// A pattern's keywords run in source order, so the receiver and method of
/// the proven call come first; later identifiers only widen the sweep.
const MAX_SEEDED_KEYWORDS_PER_PATTERN: usize = 4;

pub(crate) fn seed_catalog_with_variant_patterns(
    mut catalog: Vec<TaintIrisNextRankedCatalogEntry>,
    threat_model: Option<&Value>,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    let Some(document) = threat_model else {
        return catalog;
    };
    for pattern in crate::capabilities::threat_model::threat_variant_patterns(document) {
        seed_matching_entries(&mut catalog, pattern);
    }
    catalog
}

fn seed_matching_entries(catalog: &mut [TaintIrisNextRankedCatalogEntry], pattern: &Value) {
    let Some(cwe) = pattern.get("cwe").and_then(Value::as_str) else {
        return;
    };
    for entry in catalog.iter_mut().filter(|entry| entry.cwe.eq_ignore_ascii_case(cwe)) {
        seed_entry(entry, pattern);
    }
}

fn seed_entry(entry: &mut TaintIrisNextRankedCatalogEntry, pattern: &Value) {
    let mut added = false;
    for keyword in pattern_keywords(pattern) {
        let room = entry.structural_queries.len() < MAX_SEEDED_KEYWORDS_PER_ENTRY;
        if room && !entry.structural_queries.contains(&keyword) {
            entry.structural_queries.push(keyword);
            added = true;
        }
    }
    if added {
        entry.reasons.push(variant_reason(pattern));
    }
}

fn pattern_keywords(pattern: &Value) -> Vec<String> {
    pattern
        .get("keywords")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .take(MAX_SEEDED_KEYWORDS_PER_PATTERN)
        .map(str::to_string)
        .collect()
}

fn variant_reason(pattern: &Value) -> String {
    let location = pattern
        .get("location")
        .and_then(Value::as_str)
        .unwrap_or("unknown location");
    format!("threat-model variant pattern from a confirmed finding at {location}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(cwe: &str) -> TaintIrisNextRankedCatalogEntry {
        TaintIrisNextRankedCatalogEntry {
            cwe: cwe.to_string(),
            name: cwe.to_string(),
            taint_class: "class".to_string(),
            languages: Vec::new(),
            source_signals: Vec::new(),
            sink_signals: Vec::new(),
            sanitizer_signals: Vec::new(),
            structural_queries: vec!["SELECT".to_string()],
            regex_markers: Vec::new(),
            score: 100,
            reasons: Vec::new(),
        }
    }

    #[test]
    fn a_variant_pattern_seeds_only_its_cwe_with_new_keywords() {
        let model = json!({"threats": [{"variantPatterns": [{
            "cwe": "CWE-89",
            "location": "routes/search.ts:23",
            "keywords": ["sequelize", "query", "SELECT"]
        }]}]});

        let catalog = seed_catalog_with_variant_patterns(
            vec![entry("CWE-89"), entry("CWE-79")],
            Some(&model),
        );

        assert_eq!(catalog[0].structural_queries, vec!["SELECT", "sequelize", "query"]);
        assert!(catalog[0].reasons[0].contains("routes/search.ts:23"));
        assert_eq!(catalog[1].structural_queries, vec!["SELECT"]);
        assert!(catalog[1].reasons.is_empty());
    }

    #[test]
    fn only_the_leading_keywords_of_a_pattern_seed_the_sweep() {
        let model = json!({"threats": [{"variantPatterns": [{
            "cwe": "CWE-89",
            "keywords": ["models", "sequelize", "query", "Products", "WHERE", "email"]
        }]}]});

        let catalog = seed_catalog_with_variant_patterns(vec![entry("CWE-89")], Some(&model));

        assert_eq!(
            catalog[0].structural_queries,
            vec!["SELECT", "models", "sequelize", "query", "Products"]
        );
    }

    #[test]
    fn no_threat_model_leaves_the_catalog_unchanged() {
        let catalog = seed_catalog_with_variant_patterns(vec![entry("CWE-89")], None);

        assert_eq!(catalog[0].structural_queries, vec!["SELECT"]);
    }
}
