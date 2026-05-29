use super::*;

pub(crate) fn command_completion_candidates(prefix: &str, slash: bool) -> Vec<String> {
    let mut values = Vec::new();
    for spec in shell_command_specs() {
        let forms = std::iter::once(spec.command).chain(spec.aliases.iter().copied());
        values.extend(forms.filter_map(|form| candidate_for_prefix(form, prefix, slash)));
    }
    rank_fuzzy(dedupe_sorted(values), prefix)
}

/// Project a command/alias `form` into its completion candidate when it
/// fuzzy-matches `prefix`. `None` when it has no head, is a `?` form in slash
/// mode, or doesn't match.
fn candidate_for_prefix(form: &str, prefix: &str, slash: bool) -> Option<String> {
    let head = command_completion_head(form)?;
    if slash && head.starts_with('?') {
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
    values: Vec<String>,
) -> Vec<String> {
    let head = prefix_words.join(" ");
    let slash_prefix = if slash { "/" } else { "" };
    let matched = rank_fuzzy(dedupe_sorted(values), current);
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
