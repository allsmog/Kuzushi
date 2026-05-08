use super::*;

pub(in crate::modules) fn build_taint_iris_next_structural_queries(
    entries: &[TaintIrisNextRankedCatalogEntry],
) -> Vec<TaintIrisNextStructuralQuery> {
    let mut seen = BTreeSet::new();
    let mut queries = Vec::new();
    for entry in entries {
        for (role, patterns) in [
            ("source", &entry.source_signals),
            ("sink", &entry.sink_signals),
            ("sanitizer", &entry.sanitizer_signals),
            ("structural", &entry.structural_queries),
        ] {
            for pattern in patterns {
                let trimmed = pattern.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let key = format!("{}:{}:{}", entry.cwe, role, trimmed.to_ascii_lowercase());
                if !seen.insert(key) {
                    continue;
                }
                queries.push(TaintIrisNextStructuralQuery {
                    id: format!(
                        "{}-{}-{}",
                        entry.cwe.to_ascii_lowercase(),
                        role,
                        queries.len() + 1
                    ),
                    cwe: entry.cwe.clone(),
                    taint_class: entry.taint_class.clone(),
                    role: role.to_string(),
                    pattern: trimmed.to_string(),
                    languages: entry.languages.clone(),
                });
            }
        }
    }
    queries
}

pub(in crate::modules) fn render_taint_iris_next_catalog(
    entries: &[TaintIrisNextRankedCatalogEntry],
) -> String {
    let mut lines = vec![
        "## CWE Candidate Catalog".to_string(),
        "The agent must choose CWE themes from this catalog unless it provides customCweRationale."
            .to_string(),
        "For every selected catalog CWE, cite at least one source/sink/sanitizer/query signal."
            .to_string(),
        String::new(),
    ];
    for entry in entries {
        lines.push(format!(
            "- {}: {} [{}] score={}",
            entry.cwe, entry.name, entry.taint_class, entry.score
        ));
        lines.push(format!("  languages: {}", entry.languages.join(", ")));
        lines.push(format!(
            "  sources: {}",
            entry
                .source_signals
                .iter()
                .take(4)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
        lines.push(format!(
            "  sinks: {}",
            entry
                .sink_signals
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
        if !entry.sanitizer_signals.is_empty() {
            lines.push(format!(
                "  sanitizers: {}",
                entry
                    .sanitizer_signals
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        lines.push(format!(
            "  structural queries: {}",
            entry
                .structural_queries
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    lines.join("\n")
}
