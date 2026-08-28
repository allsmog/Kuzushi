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
    let hay = lowered_chars(haystack);
    let pat = lowered_chars(needle);
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

/// Score `needle` against `haystack` like [`subsequence_score`], but only from
/// an anchored start: the first needle character must open `haystack` or one of
/// its words.
///
/// Unanchored subsequence matching is fine for ranking a list the operator is
/// already reading. It is not safe for completing a command the next keystroke
/// can dispatch: `xu` is a subsequence of `conte`x`t b`u`ild`, so the
/// permissive form leaves a two-key typo one Enter away from running a tool
/// nobody named.
pub fn anchored_subsequence_score(haystack: &str, needle: &str) -> Option<i32> {
    let pat = lowered_chars(needle);
    let Some(&first) = pat.first() else {
        return Some(0);
    };
    let hay = lowered_chars(haystack);
    anchor_indexes(&hay, first)
        .filter_map(|start| score_from_anchor(haystack, &hay, &pat, start))
        .max()
}

fn lowered_chars(value: &str) -> Vec<char> {
    value.chars().flat_map(char::to_lowercase).collect()
}

/// Every index where `first` opens `hay` or one of its words.
fn anchor_indexes(hay: &[char], first: char) -> impl Iterator<Item = usize> + '_ {
    (0..hay.len()).filter(move |&at| hay[at] == first && opens_a_word(hay, at))
}

fn opens_a_word(hay: &[char], at: usize) -> bool {
    at == 0
        || hay
            .get(at - 1)
            .is_some_and(|ch| matches!(ch, ' ' | ':' | '-' | '.' | '_' | '/'))
}

fn score_from_anchor(haystack: &str, hay: &[char], pat: &[char], start: usize) -> Option<i32> {
    let mut score = match_bonus(start, None, haystack);
    let mut prev = start;
    let mut hay_idx = start + 1;
    for want in &pat[1..] {
        let found = hay[hay_idx..].iter().position(|c| c == want)?;
        let at = hay_idx + found;
        score += match_bonus(at, Some(prev), haystack);
        prev = at;
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
    fn anchored_empty_needle_matches_everything() {
        assert_eq!(anchored_subsequence_score("anything", ""), Some(0));
    }

    #[test]
    fn anchored_keeps_the_abbreviations_operators_actually_type() {
        for needle in ["c", "cb", "ctx", "con", "context b", "bu", "build"] {
            assert!(
                anchored_subsequence_score("context build", needle).is_some(),
                "{needle:?} should still reach `context build`"
            );
        }
    }

    #[test]
    fn anchored_rejects_a_needle_that_starts_mid_word() {
        for needle in ["xu", "on", "ild", "ext"] {
            assert_eq!(
                anchored_subsequence_score("context build", needle),
                None,
                "{needle:?} starts inside a word and must not match"
            );
        }
    }

    #[test]
    fn anchored_uses_a_later_word_start_when_the_first_hit_is_buried() {
        // The first `e` in `workspace` is buried; the anchored match is the
        // one that opens `export`.
        assert!(anchored_subsequence_score("workspace export", "ex").is_some());
        assert!(anchored_subsequence_score("taint-iris:hunt", "hunt").is_some());
        assert!(anchored_subsequence_score("taint-iris:hunt", "iris").is_some());
    }

    #[test]
    fn anchored_agrees_with_the_permissive_score_on_a_prefix_match() {
        assert_eq!(
            anchored_subsequence_score("scan", "sc"),
            subsequence_score("scan", "sc")
        );
    }

    #[test]
    fn anchored_prefers_the_highest_scoring_anchor() {
        // `s` opens both `scan` and `status`. Scoring only the first anchor
        // charges a gap penalty across the whole first word; the best anchor
        // keeps the consecutive run inside `status`.
        let hay = lowered_chars("scan status");
        let pat = lowered_chars("sta");
        let first_anchor = score_from_anchor("scan status", &hay, &pat, 0).unwrap();
        let best = anchored_subsequence_score("scan status", "sta").unwrap();
        assert!(
            best > first_anchor,
            "best anchor {best} should beat the first anchor {first_anchor}"
        );
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
