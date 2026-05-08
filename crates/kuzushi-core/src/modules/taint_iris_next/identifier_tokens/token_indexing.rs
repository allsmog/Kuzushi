use super::*;

pub(in crate::modules::taint_iris_next) fn identifier_tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .map(str::trim)
        .filter(|token| token.len() > 2)
        .map(|token| token.to_ascii_lowercase())
        .filter(|token| {
            !matches!(
                token.as_str(),
                "const"
                    | "let"
                    | "var"
                    | "def"
                    | "function"
                    | "return"
                    | "query"
                    | "request"
                    | "params"
            )
        })
        .collect()
}

pub(in crate::modules::taint_iris_next) fn cap_taint_iris_next_evidence(
    evidence: &mut Vec<TaintIrisNextEvidence>,
    max_per_cwe: usize,
) {
    let mut counts = BTreeMap::new();
    evidence.retain(|item| {
        let count = counts.entry(item.cwe.clone()).or_insert(0usize);
        if *count >= max_per_cwe {
            return false;
        }
        *count += 1;
        true
    });
}

pub(in crate::modules::taint_iris_next) fn count_taint_iris_next_candidates(
    candidates: &[TaintIrisNextCandidate],
) -> BTreeMap<String, usize> {
    candidates
        .iter()
        .fold(BTreeMap::new(), |mut counts, candidate| {
            *counts.entry(candidate.cwe.clone()).or_insert(0) += 1;
            counts
        })
}
