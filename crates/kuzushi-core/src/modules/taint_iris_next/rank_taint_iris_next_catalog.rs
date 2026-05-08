use super::*;

pub(in crate::modules) fn rank_taint_iris_next_catalog(
    languages: &[String],
    threat_cwes: &BTreeSet<String>,
    context_keywords: &str,
) -> Vec<TaintIrisNextRankedCatalogEntry> {
    let language_set = languages.iter().cloned().collect::<BTreeSet<_>>();
    let has_web = context_keywords.contains("express")
        || context_keywords.contains("fastapi")
        || context_keywords.contains("django")
        || context_keywords.contains("route")
        || context_keywords.contains("handler");
    let has_db = context_keywords.contains("sql")
        || context_keywords.contains("postgres")
        || context_keywords.contains("mysql")
        || context_keywords.contains("sqlite")
        || context_keywords.contains("prisma")
        || context_keywords.contains("sqlalchemy");

    let mut entries = TAINT_IRIS_NEXT_CATALOG
        .iter()
        .map(|entry| {
            let mut score = 0;
            let mut reasons = Vec::new();
            if threat_cwes.contains(entry.cwe) {
                score += 100;
                reasons.push("threat-model CWE".to_string());
            }
            if entry.languages.contains(&"any")
                || entry
                    .languages
                    .iter()
                    .any(|language| language_set.contains(*language))
            {
                score += 25;
                reasons.push("language match".to_string());
            }
            if entry.languages.contains(&"any") {
                score += 5;
                reasons.push("language agnostic".to_string());
            }
            if has_db && entry.taint_class.contains("sql") {
                score += 35;
                reasons.push("database/ORM context".to_string());
            }
            if has_web
                && matches!(
                    entry.taint_class,
                    "xss" | "ssrf" | "missing-authorization" | "sql-injection" | "path-traversal"
                )
            {
                score += 20;
                reasons.push("web entrypoint context".to_string());
            }
            let hits = entry
                .source_signals
                .iter()
                .chain(entry.sink_signals.iter())
                .chain(entry.structural_queries.iter())
                .filter(|signal| context_keywords.contains(&signal.to_ascii_lowercase()))
                .count() as i32;
            if hits > 0 {
                score += (hits * 5).min(30);
                reasons.push("context keyword overlap".to_string());
            }
            TaintIrisNextRankedCatalogEntry {
                cwe: entry.cwe.to_string(),
                name: entry.name.to_string(),
                taint_class: entry.taint_class.to_string(),
                languages: entry
                    .languages
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                source_signals: entry
                    .source_signals
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                sink_signals: entry
                    .sink_signals
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                sanitizer_signals: entry
                    .sanitizer_signals
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                structural_queries: entry
                    .structural_queries
                    .iter()
                    .map(|item| item.to_string())
                    .collect(),
                score,
                reasons,
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| cwe_number(&left.cwe).cmp(&cwe_number(&right.cwe)))
    });
    entries
}
