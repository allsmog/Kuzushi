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
/// - A token without `:` is a free-text term.
pub fn tokenize_filter_expression(expr: &str) -> Result<Vec<FilterToken>> {
    expr.split_whitespace()
        .filter(|token| !token.trim().is_empty())
        .map(parse_token)
        .collect()
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
    let values = split_csv(raw_value);
    if values.is_empty() {
        anyhow::bail!("filter {key:?} requires a value");
    }
    Ok(FilterToken {
        key: Some(key.to_string()),
        values,
        raw: token.to_string(),
    })
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
}
