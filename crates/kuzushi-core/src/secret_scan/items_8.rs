use super::prelude::*;
use super::*;

pub(crate) fn detect_assignments(
    text: &str,
    keys: &[&str],
    detector: Detector,
    mode: AssignmentMode,
    value_char: fn(u8) -> bool,
    hits: &mut Vec<SecretHit>,
) {
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let lower_bytes = lower.as_bytes();
    for index in 0..bytes.len() {
        if index > 0 && is_identifier_byte(bytes[index - 1]) {
            continue;
        }

        for key in keys {
            let key_bytes = key.as_bytes();
            if !lower_bytes[index..].starts_with(key_bytes) {
                continue;
            }
            let mut cursor = index + key_bytes.len();
            if cursor < bytes.len() && is_identifier_byte(bytes[cursor]) {
                continue;
            }
            cursor = skip_ascii_whitespace(bytes, cursor);
            if cursor >= bytes.len() || (bytes[cursor] != b':' && bytes[cursor] != b'=') {
                continue;
            }
            cursor += 1;
            cursor = skip_ascii_whitespace(bytes, cursor);

            let quote = if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'')
            {
                let quote = bytes[cursor];
                cursor += 1;
                Some(quote)
            } else {
                None
            };
            if matches!(mode, AssignmentMode::RequiredQuote) && quote.is_none() {
                continue;
            }

            let value_start = cursor;
            while cursor < bytes.len() && value_char(bytes[cursor]) {
                cursor += 1;
            }
            if cursor - value_start < 16 {
                continue;
            }
            if let Some(quote) = quote {
                if cursor >= bytes.len() || bytes[cursor] != quote {
                    continue;
                }
            }

            let value = &text[value_start..cursor];
            if let Some(threshold) = detector.entropy_threshold {
                if shannon_entropy(value) < threshold {
                    continue;
                }
            }
            let matched = &text[index..cursor];
            push_hit(hits, detector, matched, value, index);
        }
    }
}

pub(crate) fn push_hit(
    hits: &mut Vec<SecretHit>,
    detector: Detector,
    matched: &str,
    captured_secret: &str,
    index: usize,
) {
    hits.push(SecretHit {
        detector,
        matched: matched.to_string(),
        captured_secret: captured_secret.to_string(),
        index,
    });
}

pub(crate) fn matches_prefixed_token(
    token: &str,
    prefixes: &[&str],
    min_rest: usize,
    rest_char: fn(u8) -> bool,
) -> bool {
    prefixes.iter().any(|prefix| {
        token
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.len() >= min_rest && rest.bytes().all(rest_char))
    })
}

pub(crate) fn looks_like_jwt(token: &str) -> bool {
    let parts = token.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts[0].len() >= 11
        && parts[1].len() >= 8
        && parts[2].len() >= 4
        && parts
            .iter()
            .all(|part| part.bytes().all(is_alnum_underscore_hyphen))
}
