use super::*;

pub(crate) fn command_completion_candidates(prefix: &str, slash: bool) -> Vec<String> {
    let mut values = Vec::new();
    for spec in shell_command_specs() {
        for form in std::iter::once(spec.command).chain(spec.aliases.iter().copied()) {
            let Some(head) = command_completion_head(form) else {
                continue;
            };
            if slash && head.starts_with('?') {
                continue;
            }
            let candidate = if slash && !head.starts_with('/') {
                format!("/{head}")
            } else {
                head
            };
            let comparable = candidate.strip_prefix('/').unwrap_or(&candidate);
            if comparable.starts_with(prefix) || candidate.starts_with(prefix) {
                values.push(candidate);
            }
        }
    }
    dedupe_sorted(values)
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
    let current_lower = current.to_ascii_lowercase();
    let head = prefix_words.join(" ");
    let slash_prefix = if slash { "/" } else { "" };
    let candidates = values
        .into_iter()
        .filter(|value| {
            current_lower.is_empty() || value.to_ascii_lowercase().starts_with(&current_lower)
        })
        .map(|value| {
            if head.is_empty() {
                format!("{slash_prefix}{value}")
            } else {
                format!("{slash_prefix}{head} {value}")
            }
        })
        .collect();
    dedupe_sorted(candidates)
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
