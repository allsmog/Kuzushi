use anyhow::Result;

/// A single whitespace-delimited token of a filter expression.
///
/// - Keyed token `severity:high,medium` → `key = Some("severity")`,
///   `values = ["high", "medium"]`.
/// - Bare token `injection` → `key = None`, `values = []`, `raw = "injection"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterToken {
    /// The key before the first `:`, or `None` for a free-text term.
    pub key: Option<String>,
    /// CSV-split values after the `:` (trimmed, non-empty). Empty for free text.
    pub values: Vec<String>,
    /// The original whitespace token, verbatim.
    pub raw: String,
}

impl FilterToken {
    /// True when this token is a bare free-text term (no `key:`).
    pub fn is_free_text(&self) -> bool {
        self.key.is_none()
    }
}

/// Tokenize a filter expression into keyed and free-text tokens.
///
/// Rules (shared by findings and tool queries):
/// - Whitespace splits tokens.
/// - A leading `-` is reserved for negation, which is not supported yet — it is
///   an explicit error rather than a silent drop.
/// - The first `:` splits a keyed token into key + CSV values; a keyed token
///   with no non-empty value is an error.
/// - `files:` accepts a JSON string array to retain spaces, commas and escapes
///   inside each path. The next token must be separated by whitespace.
/// - A token without `:` is a free-text term.
pub fn tokenize_filter_expression(expr: &str) -> Result<Vec<FilterToken>> {
    let mut remaining = expr.trim_start();
    let mut tokens = Vec::new();
    while !remaining.is_empty() {
        let (token, rest) = take_filter_token(remaining)?;
        tokens.push(parse_token(token)?);
        remaining = rest.trim_start();
    }
    Ok(tokens)
}

fn take_filter_token(input: &str) -> Result<(&str, &str)> {
    let end = match json_value_start(input) {
        Some(start) => json_token_end(input, start)?,
        None => input.find(char::is_whitespace).unwrap_or(input.len()),
    };
    Ok(input.split_at(end))
}

fn json_value_start(input: &str) -> Option<usize> {
    let colon = input.find(':')?;
    if !input[..colon].eq_ignore_ascii_case("files") {
        return None;
    }
    input[colon + 1..].starts_with('[').then_some(colon + 1)
}

fn json_token_end(input: &str, start: usize) -> Result<usize> {
    let mut values = serde_json::Deserializer::from_str(&input[start..]).into_iter::<Vec<String>>();
    values.next().transpose()?;
    let end = start + values.byte_offset();
    anyhow::ensure!(
        input[end..].chars().next().is_none_or(char::is_whitespace),
        "JSON filter values must be followed by whitespace"
    );
    Ok(end)
}

fn parse_token(token: &str) -> Result<FilterToken> {
    if token.starts_with('-') {
        anyhow::bail!("filter negation is not supported yet: {token:?}");
    }
    let Some((key, raw_value)) = token.split_once(':') else {
        return Ok(FilterToken {
            key: None,
            values: Vec::new(),
            raw: token.to_string(),
        });
    };
    let values = parse_values(key, raw_value)?;
    if values.is_empty() {
        anyhow::bail!("filter {key:?} requires a value");
    }
    Ok(FilterToken {
        key: Some(key.to_string()),
        values,
        raw: token.to_string(),
    })
}

fn parse_values(key: &str, value: &str) -> Result<Vec<String>> {
    if key.eq_ignore_ascii_case("files") && value.starts_with('[') {
        let values: Vec<String> = serde_json::from_str(value)?;
        return Ok(values
            .into_iter()
            .filter(|value| !value.is_empty())
            .collect());
    }
    Ok(split_csv(value))
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_keyed_csv_values() {
        let tokens = tokenize_filter_expression("severity:high,medium").unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].key.as_deref(), Some("severity"));
        assert_eq!(tokens[0].values, vec!["high", "medium"]);
        assert!(!tokens[0].is_free_text());
    }

    #[test]
    fn bare_token_is_free_text() {
        let tokens = tokenize_filter_expression("injection").unwrap();
        assert_eq!(tokens[0].key, None);
        assert!(tokens[0].is_free_text());
        assert_eq!(tokens[0].raw, "injection");
    }

    #[test]
    fn mixes_keyed_and_free_text() {
        let tokens = tokenize_filter_expression("phase:hunt taint runtime:agentic").unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].key.as_deref(), Some("phase"));
        assert!(tokens[1].is_free_text());
        assert_eq!(tokens[2].key.as_deref(), Some("runtime"));
    }

    #[test]
    fn negation_is_rejected() {
        let error = tokenize_filter_expression("-severity:high").unwrap_err();
        assert!(error.to_string().contains("negation"));
    }

    #[test]
    fn keyed_token_requires_value() {
        let error = tokenize_filter_expression("severity:").unwrap_err();
        assert!(error.to_string().contains("requires a value"));
    }

    #[test]
    fn empty_expression_yields_no_tokens() {
        assert!(tokenize_filter_expression("   ").unwrap().is_empty());
    }

    #[test]
    fn json_values_preserve_literal_paths_and_following_filters() {
        let paths = vec!["src/a b.rs", "src/a,b.rs", "src/α\\quoted\".rs"];
        let expression = format!("files:{} severity:high", serde_json::json!(paths));
        let tokens = tokenize_filter_expression(&expression).unwrap();
        assert_eq!(tokens[0].key.as_deref(), Some("files"));
        assert_eq!(tokens[0].values, paths);
        assert_eq!(tokens[1].values, ["high"]);
    }

    #[test]
    fn invalid_json_values_are_errors() {
        for input in ["files:[", "files:[]", "files:[1]", "files:[\"a\"]tail"] {
            assert!(tokenize_filter_expression(input).is_err(), "{input}");
        }
    }

    #[test]
    fn legacy_csv_and_unquoted_backslashes_are_unchanged() {
        let tokens =
            tokenize_filter_expression(r"file:src\legacy.rs rank:high,medium file:[a-z].rs")
                .unwrap();
        assert_eq!(tokens[0].values, [r"src\legacy.rs"]);
        assert_eq!(tokens[1].values, ["high", "medium"]);
        assert_eq!(tokens[2].values, ["[a-z].rs"]);
    }
}
