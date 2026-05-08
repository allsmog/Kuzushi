use super::*;

pub(crate) fn matching_tokens(corpus: &str, candidates: &[&str]) -> Vec<String> {
    candidates
        .iter()
        .filter(|token| corpus.contains(&token.to_ascii_lowercase()))
        .map(|token| (*token).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn tokens_present(corpus: &str, tokens: &[String]) -> bool {
    tokens
        .iter()
        .any(|token| corpus.contains(&token.to_ascii_lowercase()))
}

pub(crate) fn contains_any(corpus: &str, tokens: &[&str]) -> bool {
    tokens
        .iter()
        .any(|token| corpus.contains(&token.to_ascii_lowercase()))
}

pub(crate) fn guarded_negative_fixture(positive_body: &str) -> String {
    format!(
        "const kuzushiCandidateValue = sanitize(req.query.kuzushi);\n{}\n",
        positive_body
    )
}

pub(crate) fn semgrep_language_for_path(path: &str) -> String {
    match path.rsplit('.').next().unwrap_or_default() {
        "js" | "jsx" | "mjs" | "cjs" => "javascript",
        "ts" | "tsx" => "typescript",
        "py" => "python",
        "go" => "go",
        "rs" => "rust",
        "java" => "java",
        "kt" => "kotlin",
        "rb" => "ruby",
        "php" => "php",
        "c" | "h" => "c",
        "cc" | "cpp" | "hpp" => "cpp",
        _ => "generic",
    }
    .to_string()
}

pub(crate) fn candidate_slug(rule_id: &str, fingerprint: &str) -> String {
    let mut slug = rule_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect::<String>();
    while slug.contains("..") {
        slug = slug.replace("..", ".");
    }
    let slug = slug.trim_matches('.');
    let suffix = fingerprint.chars().take(8).collect::<String>();
    if slug.is_empty() {
        suffix
    } else {
        format!("{slug}.{suffix}")
    }
}

pub(crate) fn regex_escape(value: &str) -> String {
    let mut escaped = String::new();
    for ch in value.chars() {
        if matches!(
            ch,
            '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
        ) {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}
