use super::*;

pub(crate) fn command_completion_candidates(prefix: &str, slash: bool) -> Vec<String> {
    let mut values = Vec::new();
    for spec in shell_command_specs() {
        let base_head = command_completion_head(spec.command);
        values.extend(candidate_for_prefix(spec.command, prefix, slash));
        let aliases = spec
            .aliases
            .iter()
            .copied()
            .filter(|alias| !is_value_filled_example(base_head.as_deref(), alias));
        values.extend(aliases.filter_map(|alias| candidate_for_prefix(alias, prefix, slash)));
    }
    rank_fuzzy(dedupe_sorted(values), prefix)
}

/// An alias is a value-filled `/help` usage example — not a distinct
/// routable form — when its own (placeholder-truncated) head has strictly
/// more words than the base command's own head and shares that head as a
/// literal word-for-word prefix (ignoring a leading `/`). That is exactly
/// the shape produced by substituting a concrete value for the command's
/// own placeholder: `"model 1"` extends `"model [choice]"`'s truncated
/// head `"model"` with the filled-in choice.
///
/// A genuine routed synonym instead REPLACES one of the base head's own
/// words in place and keeps the same word count — `"patch discard"` vs.
/// `"patch reject"`, `"strategy run"` vs. `"strategy fire"`, `"threats
/// history"` vs. `"threats versions"` — so it is left untouched. See #172
/// finding 6 and its follow-up review comment.
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
    let matches = subsequence_score(comparable, prefix).is_some()
        || subsequence_score(&candidate, prefix).is_some();
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
