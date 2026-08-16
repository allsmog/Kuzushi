use super::*;

pub(crate) fn command_completion_candidates(prefix: &str, slash: bool) -> Vec<String> {
    let mut values = Vec::new();
    for spec in shell_command_specs() {
        values.extend(candidate_for_prefix(spec.command, prefix, slash));
        let aliases = spec
            .aliases
            .iter()
            .copied()
            .filter(|alias| !is_value_filled_example(alias));
        values.extend(aliases.filter_map(|alias| candidate_for_prefix(alias, prefix, slash)));
    }
    rank_fuzzy(dedupe_sorted(values), prefix)
}

/// A `ShellCommandSpec` alias is a value-filled `/help` usage example (e.g.
/// `"model 1"`) rather than a distinct routable form when every one of its
/// words is a literal (none carry `<`/`[`/`|` placeholder syntax) and it has
/// more than one word. Real alternate routes stay single words (`"/auth"`,
/// `"attachments"`) or keep their placeholders (`"/model [choice]"`);
/// command routing (`known_command_head`) only ever needs an alias's first
/// word, so a multi-word literal example adds no completion value — it only
/// risks fuzzy-matching an unrelated short input (see #172 finding 6, where a
/// bare `1` matched the `"model 1"` example and Tab-completed into a
/// model-switch command).
fn is_value_filled_example(alias: &str) -> bool {
    let mut words = alias.split_whitespace().peekable();
    words.next(); // first word may be a legitimate synonym on its own
    words.peek().is_some() && !alias.contains(['<', '[', '|'])
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
