use super::*;

pub(in crate::scan) fn parse_codeql_language_list(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if let Some(languages) = parse_codeql_language_json(trimmed) {
        return languages;
    }

    dedupe_codeql_languages(trimmed.lines().filter_map(normalize_codeql_language))
}

pub(in crate::scan) fn parse_codeql_language_json(raw: &str) -> Option<Vec<String>> {
    let parsed = serde_json::from_str::<Value>(raw).ok()?;
    let languages = dedupe_codeql_languages(languages_from_codeql_json(parsed));
    (!languages.is_empty()).then_some(languages)
}

pub(in crate::scan) fn languages_from_codeql_json(parsed: Value) -> Vec<String> {
    match parsed {
        Value::Array(values) => values.iter().filter_map(language_from_value).collect(),
        Value::Object(map) => languages_from_codeql_object(&map),
        _ => Vec::new(),
    }
}

pub(in crate::scan) fn languages_from_codeql_object(
    map: &serde_json::Map<String, Value>,
) -> Vec<String> {
    match map.get("languages") {
        Some(Value::Array(values)) => values.iter().filter_map(language_from_value).collect(),
        _ => map
            .keys()
            .filter_map(|key| normalize_codeql_language(key))
            .collect(),
    }
}

pub(in crate::scan) fn dedupe_codeql_languages<I>(languages: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut languages = languages.into_iter().collect::<Vec<_>>();
    languages.sort();
    languages.dedup();
    languages
}

pub(in crate::scan) fn language_from_value(value: &Value) -> Option<String> {
    match value {
        Value::String(language) => normalize_codeql_language(language),
        Value::Object(map) => map
            .get("name")
            .and_then(Value::as_str)
            .and_then(normalize_codeql_language),
        _ => None,
    }
}

pub(in crate::scan) fn normalize_codeql_language(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    non_empty_string(&normalized)
        .and_then(|language| codeql_language_rule_for(language).map(str::to_string))
}
