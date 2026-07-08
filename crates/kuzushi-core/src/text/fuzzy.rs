//! Small, dependency-free fuzzy matcher shared by the tool catalog query, the
//! command completion, and the command palette. Pure functions — no IO, no
//! terminal — so they are trivially testable.

/// Score `needle` against `haystack` as a case-insensitive subsequence.
/// Returns `None` when `needle` is not a subsequence of `haystack`. A higher
/// score is a better match. An empty needle matches everything with score 0 so
/// callers can keep their "list all" behavior.
pub fn subsequence_score(haystack: &str, needle: &str) -> Option<i32> {
    if needle.is_empty() {
        return Some(0);
    }
    let hay: Vec<char> = haystack.chars().flat_map(char::to_lowercase).collect();
    let pat: Vec<char> = needle.chars().flat_map(char::to_lowercase).collect();
    let mut score = 0;
    let mut hay_idx = 0;
    let mut prev_match: Option<usize> = None;
    for want in &pat {
        let found = hay[hay_idx..].iter().position(|c| c == want)?;
        let at = hay_idx + found;
        score += match_bonus(at, prev_match, haystack);
        prev_match = Some(at);
        hay_idx = at + 1;
    }
    Some(score)
}

fn match_bonus(at: usize, prev_match: Option<usize>, haystack: &str) -> i32 {
    let mut bonus = 0;
    if at == 0 {
        bonus += 12; // prefix match
    } else if is_word_start(haystack, at) {
        bonus += 6; // start of a word/segment
    }
    match prev_match {
        Some(prev) if prev + 1 == at => bonus += 4, // consecutive run
        Some(prev) => bonus -= (at - prev - 1).min(6) as i32, // gap penalty
        None => {}
    }
    bonus
}

fn is_word_start(haystack: &str, at: usize) -> bool {
    haystack
        .chars()
        .nth(at.saturating_sub(1))
        .map(|c| matches!(c, ' ' | ':' | '-' | '.' | '_' | '/'))
        .unwrap_or(false)
}

/// Rank `candidates` by fuzzy score against `needle`, dropping non-matches.
/// Stable: equal scores keep their original order.
pub fn rank_fuzzy(candidates: Vec<String>, needle: &str) -> Vec<String> {
    let mut scored: Vec<(i32, usize, String)> = candidates
        .into_iter()
        .enumerate()
        .filter_map(|(idx, value)| {
            subsequence_score(&value, needle).map(|score| (score, idx, value))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, _, value)| value).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_needle_matches_everything() {
        assert_eq!(subsequence_score("anything", ""), Some(0));
    }

    #[test]
    fn non_subsequence_returns_none() {
        assert_eq!(subsequence_score("scan", "xyz"), None);
    }

    #[test]
    fn matches_non_contiguous_subsequence() {
        assert!(subsequence_score("semgrep:scan", "sgsc").is_some());
        assert!(subsequence_score("semgrep:scan", "smgrp").is_some());
    }

    #[test]
    fn prefix_match_outranks_midword_match() {
        let prefix = subsequence_score("scan", "sc").unwrap();
        let midword = subsequence_score("myscan", "sc").unwrap();
        assert!(prefix > midword, "{prefix} should beat {midword}");
    }

    #[test]
    fn word_start_outranks_buried_match() {
        let segment = subsequence_score("run:scan", "scan").unwrap();
        let buried = subsequence_score("rescans", "scan").unwrap();
        assert!(segment > buried, "{segment} should beat {buried}");
    }

    #[test]
    fn rank_is_stable_for_equal_scores() {
        let ranked = rank_fuzzy(vec!["alpha".to_string(), "alto".to_string()], "al");
        assert_eq!(ranked, vec!["alpha".to_string(), "alto".to_string()]);
    }

    #[test]
    fn rank_drops_non_matches() {
        let ranked = rank_fuzzy(vec!["scan".to_string(), "findings".to_string()], "scn");
        assert_eq!(ranked, vec!["scan".to_string()]);
    }
}
