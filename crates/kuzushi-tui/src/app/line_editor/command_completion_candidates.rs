use super::*;

pub(crate) fn command_completion_candidates(prefix: &str, slash: bool) -> Vec<String> {
    let mut values = Vec::new();
    for spec in shell_command_specs() {
        let base_head = command_completion_head(spec.command);
        values.extend(candidate_for_prefix(spec.command, prefix, slash));
        let forms = spec
            .aliases
            .iter()
            .copied()
            .filter_map(|alias| alias_completion_form(base_head.as_deref(), alias));
        values.extend(forms.filter_map(|form| candidate_for_prefix(&form, prefix, slash)));
    }
    rank_fuzzy(dedupe_sorted(values), prefix)
}

/// Project an alias onto the command form an operator can actually type.
///
/// `/help` lists aliases as filled-in usage examples, so an alias routinely
/// carries concrete argument values that its routed form never contains:
/// `"model 1"`, `"/x F-0001 --reason false-positive"`. Completing into one
/// drafts a command with no relation to what was typed — a bare `1` is a
/// subsequence of both, and the second suppresses a finding nobody named.
/// Keep the alias's head up to its first filled-in value, then drop whatever
/// survives when it is only a value-filled restatement of the base command.
/// `None` when nothing routable is left. See #172 finding 6.
fn alias_completion_form(base_head: Option<&str>, alias: &str) -> Option<String> {
    let head = command_completion_head(alias)?;
    let words: Vec<&str> = head
        .split_whitespace()
        .take_while(|word| !is_filled_in_value(word))
        .collect();
    if words.is_empty() {
        return None;
    }
    let form = words.join(" ");
    (!is_value_filled_example(base_head, &form)).then_some(form)
}

/// Shell command words are lowercase and digit-free (`show aliases`,
/// `taint-iris:hunt`), so a word carrying a digit or an uppercase letter is a
/// value substituted into a usage example (`1`, `F-0001`), never part of the
/// routed form. Truncating there is what keeps an example written against a
/// short synonym (`/x` for `suppress`) out of the completion pool, which the
/// base-head comparison below cannot see.
fn is_filled_in_value(word: &str) -> bool {
    word.chars()
        .any(|ch| ch.is_ascii_digit() || ch.is_ascii_uppercase())
}

/// An alias is a value-filled `/help` usage example — not a distinct
/// routable form — when its own (placeholder-truncated) head has strictly
/// more words than the base command's own head and shares that head as a
/// literal word-for-word prefix (ignoring a leading `/`). That is exactly
/// the shape produced by spelling out the command's own placeholder in
/// words: `"dismiss false_positive not reachable in prod"` extends
/// `"dismiss <reason> <note>"`'s truncated head `"dismiss"`.
///
/// A genuine routed synonym instead REPLACES one of the base head's own
/// words in place and keeps the same word count — `"patch discard"` vs.
/// `"patch reject"`, `"strategy run"` vs. `"strategy fire"`, `"threats
/// history"` vs. `"threats versions"` — so it is left untouched, as is a
/// synonym that names more words than the base command does (`"show
/// modules"` for `"modules"`). See #172 finding 6 and its follow-up review
/// comment.
fn is_value_filled_example(base_head: Option<&str>, alias: &str) -> bool {
    let Some(base_head) = base_head else {
        return false;
    };
    let Some(alias_head) = command_completion_head(alias) else {
        return false;
    };
    let base_words: Vec<&str> = base_head.split_whitespace().collect();
    let alias_words: Vec<&str> = alias_head.split_whitespace().collect();
    alias_words.len() > base_words.len()
        && alias_words
            .iter()
            .map(|word| word.trim_start_matches('/'))
            .zip(base_words)
            .all(|(alias_word, base_word)| alias_word == base_word)
}

/// Project a command/alias `form` into its completion candidate when it
/// fuzzy-matches `prefix`. `None` when it has no head, is a `?` form in slash
/// mode, or doesn't match.
///
/// The match is *anchored*: the first typed character must open the command or
/// one of its words. Completion here is not a list to browse — the row it
/// drafts is one Enter away from dispatching a tool — so an unanchored
/// subsequence is too generous. `xu` is a subsequence of `context build`
/// (conte**x**t b**u**ild), and offering that run to two stray keystrokes is
/// how an operator dispatches something nobody named. Ranking below stays on
/// the permissive scorer; it only orders rows this filter already admitted.
fn candidate_for_prefix(form: &str, prefix: &str, slash: bool) -> Option<String> {
    let head = command_completion_head(form)?;
    if slash && head.starts_with('?') {
        return None;
    }
    if slash && head.contains(' ') {
        return None;
    }
    let candidate = if slash && !head.starts_with('/') {
        format!("/{head}")
    } else {
        head
    };
    let comparable = candidate.strip_prefix('/').unwrap_or(&candidate);
    let matches = anchored_subsequence_score(comparable, prefix).is_some()
        || anchored_subsequence_score(&candidate, prefix).is_some();
    matches.then_some(candidate)
}

pub(crate) fn command_completion_head(template: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in template.split_whitespace() {
        if part.contains('<') || part.contains('[') || part.contains('|') {
            break;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

pub(crate) fn complete_value_candidates(
    slash: bool,
    prefix_words: &[&str],
    current: &str,
    values: CompletionValues<'_>,
) -> Vec<String> {
    let head = prefix_words.join(" ");
    let slash_prefix = if slash { "/" } else { "" };
    let matched = rank_completion_values(values, current);
    matched
        .into_iter()
        .map(|value| {
            if head.is_empty() {
                format!("{slash_prefix}{value}")
            } else {
                format!("{slash_prefix}{head} {value}")
            }
        })
        .collect()
}

fn rank_completion_values(values: CompletionValues<'_>, current: &str) -> Vec<String> {
    match values {
        CompletionValues::Owned(values) => {
            rank_matching_refs(values.iter().map(String::as_str), current)
        }
        CompletionValues::Static(values) => rank_matching_refs(values.iter().copied(), current),
        CompletionValues::Borrowed(values) => {
            rank_matching_refs(values.iter().map(String::as_str), current)
        }
        CompletionValues::RunIds { live, stored } => rank_matching_refs(
            live.into_iter()
                .flatten()
                .chain(stored.iter().map(String::as_str)),
            current,
        ),
    }
}

fn rank_matching_refs<'a>(values: impl Iterator<Item = &'a str>, current: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let matched = values
        .filter(|value| subsequence_score(value, current).is_some())
        .filter(|value| seen.insert(*value))
        .map(str::to_string)
        .collect();
    rank_fuzzy(matched, current)
}

pub(crate) fn dedupe_sorted(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

pub(crate) fn config_completion_keys() -> &'static [&'static str] {
    &[
        "model",
        "runtime.kind",
        "runtime.api_key_env",
        "runtime.langgraph_bridge_command",
        "target",
        "workspace",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_prefixes_still_reach_the_command_they_abbreviate() {
        // Positive controls first: anchoring must not cost the operator the
        // abbreviations they actually type.
        for (prefix, expected) in [
            ("cb", "context build"),
            ("ctx", "context"),
            ("con", "context"),
            ("con", "context build"),
            ("cs", "context status"),
        ] {
            let candidates = command_completion_candidates(prefix, false);
            assert!(
                candidates.iter().any(|candidate| candidate == expected),
                "{prefix:?} no longer reaches {expected:?}: {candidates:?}"
            );
        }
    }

    #[test]
    fn a_mid_word_prefix_does_not_complete_into_a_dispatchable_run() {
        // `xu` is a subsequence of `conte`x`t b`u`ild` but opens no word in it.
        let candidates = command_completion_candidates("xu", false);
        assert!(
            !candidates.iter().any(|candidate| candidate == "context build"),
            "`xu` completed into a tool run: {candidates:?}"
        );
    }

    #[test]
    fn every_two_char_prefix_completes_only_at_a_word_start() {
        // Repo-wide guard, in the spirit of the alias invariant below: the
        // hazard is structural, so pin it over every registered spec and every
        // two-key prefix rather than over the one pair that happened to be
        // dangerous. Two characters is the shortest prefix a completion is
        // offered for, so it is where an unanchored match does the most damage.
        for first in 'a'..='z' {
            for second in 'a'..='z' {
                let prefix = format!("{first}{second}");
                for candidate in command_completion_candidates(&prefix, false) {
                    assert!(
                        opens_a_word_of(&candidate, first),
                        "{prefix:?} completed into {candidate:?}, which does not start it"
                    );
                }
            }
        }
    }

    fn opens_a_word_of(candidate: &str, first: char) -> bool {
        let chars: Vec<char> = candidate.chars().collect();
        chars.iter().enumerate().any(|(at, ch)| {
            ch.eq_ignore_ascii_case(&first)
                && (at == 0 || matches!(chars[at - 1], ' ' | ':' | '-' | '.' | '_' | '/'))
        })
    }

    #[test]
    fn no_alias_completes_into_a_filled_in_example_value() {
        // Repo-wide guard: the hazard resurfaces whenever a spec author adds
        // an example alias carrying a concrete value, so pin the invariant
        // over every registered spec rather than over the one alias that
        // happened to be dangerous this time.
        for spec in shell_command_specs() {
            let base_head = command_completion_head(spec.command);
            for alias in spec.aliases {
                let Some(form) = alias_completion_form(base_head.as_deref(), alias) else {
                    continue;
                };
                assert!(
                    !form.split_whitespace().any(is_filled_in_value),
                    "alias {alias:?} completes into example values: {form:?}"
                );
            }
        }
    }

    #[test]
    fn alias_completion_form_keeps_routed_heads_and_drops_example_values() {
        assert_eq!(
            alias_completion_form(Some("suppress"), "/x F-0001 --reason false-positive"),
            Some("/x".to_string()),
            "a short synonym stays reachable without its example arguments"
        );
        assert_eq!(
            alias_completion_form(Some("model"), "model 1"),
            Some("model".to_string())
        );
        assert_eq!(
            alias_completion_form(Some("modules"), "show modules"),
            Some("show modules".to_string()),
            "a synonym may name more words than the base command"
        );
        assert_eq!(
            alias_completion_form(Some("patch reject"), "patch discard"),
            Some("patch discard".to_string())
        );
        assert_eq!(
            alias_completion_form(
                Some("dismiss"),
                "dismiss false_positive not reachable in prod"
            ),
            None,
            "a spelled-out restatement of the base command is not a routed form"
        );
    }
}
