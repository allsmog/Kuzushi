use super::prelude::*;
use super::*;

pub(crate) fn threat_search_text(threat: &Value) -> String {
    let mut parts = Vec::new();
    for key in ["title", "description", "attackVector", "attack_vector"] {
        if let Some(value) = object_string_value(threat, &[key]) {
            parts.push(value);
        }
    }
    for key in [
        "requiredCapabilities",
        "required_capabilities",
        "preconditions",
        "targetElementIds",
        "target_element_ids",
    ] {
        parts.extend(object_string_array(threat, &[key]));
    }
    for key in [
        "sources",
        "sinks",
        "guards",
        "sanitizers",
        "evidenceAnchors",
        "evidence_anchors",
    ] {
        if let Some(items) = threat.get(key).and_then(Value::as_array) {
            for item in items {
                for field in [
                    "name",
                    "kind",
                    "elementId",
                    "element_id",
                    "description",
                    "filePath",
                    "file_path",
                    "symbol",
                    "snippet",
                ] {
                    if let Some(value) = object_string_value(item, &[field]) {
                        parts.push(value);
                    }
                }
            }
        }
    }
    parts.join(" ").to_ascii_lowercase()
}

pub(crate) fn actor_semantic_score(actor: &DfdNode, haystack: &str) -> usize {
    let label = format!("{} {} {}", actor.id, actor.name, actor.description).to_ascii_lowercase();
    let mut score = 0usize;
    if haystack.contains(&actor.id.to_ascii_lowercase()) {
        score += 5;
    }
    for token in actor_tokens(actor) {
        if haystack.contains(&token) {
            score += 1;
        }
    }
    for (needle, actor_terms, boost) in [
        (
            "pull request fork branch contributor",
            "pr author fork contributor developer",
            4usize,
        ),
        (
            "comment issue review slash command",
            "commenter comment issue",
            4usize,
        ),
        (
            "admin owner maintainer platform",
            "admin owner maintainer platform",
            3usize,
        ),
        ("bot github app app token", "bot github app", 2usize),
    ] {
        if needle
            .split_whitespace()
            .any(|word| haystack.contains(word))
            && actor_terms
                .split_whitespace()
                .any(|word| label.contains(word))
        {
            score += boost;
        }
    }
    score
}

pub(crate) fn actor_tokens(actor: &DfdNode) -> Vec<String> {
    let stop = BTreeSet::from([
        "actor", "api", "app", "bot", "external", "github", "http", "https", "internal", "service",
        "user",
    ]);
    unique_strings(
        format!("{} {} {}", actor.id, actor.name, actor.description)
            .to_ascii_lowercase()
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-')
            .filter(|token| token.len() >= 4 && !stop.contains(*token))
            .map(ToString::to_string)
            .collect(),
    )
}
