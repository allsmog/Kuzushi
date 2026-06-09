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
        if !is_assignment_start(bytes, index) {
            continue;
        }

        for key in keys {
            if let Some(assignment) = assignment_at(
                text,
                bytes,
                lower_bytes,
                index,
                key,
                mode,
                value_char,
                detector,
            ) {
                push_hit(
                    hits,
                    detector,
                    assignment.matched,
                    assignment.value,
                    assignment.index,
                );
            }
        }
    }
}

struct AssignmentMatch<'a> {
    matched: &'a str,
    value: &'a str,
    index: usize,
}

fn is_assignment_start(bytes: &[u8], index: usize) -> bool {
    index == 0 || !is_identifier_byte(bytes[index - 1])
}

fn assignment_at<'a>(
    text: &'a str,
    bytes: &[u8],
    lower_bytes: &[u8],
    index: usize,
    key: &str,
    mode: AssignmentMode,
    value_char: fn(u8) -> bool,
    detector: Detector,
) -> Option<AssignmentMatch<'a>> {
    let cursor = cursor_after_assignment_key(bytes, lower_bytes, index, key)?;
    let (cursor, quote) = cursor_after_assignment_operator(bytes, cursor, mode)?;
    let value_end = assignment_value_end(bytes, cursor, quote, value_char)?;
    let value = &text[cursor..value_end];
    if !assignment_entropy_passes(value, detector) {
        return None;
    }
    Some(AssignmentMatch {
        matched: &text[index..value_end],
        value,
        index,
    })
}

fn cursor_after_assignment_key(
    bytes: &[u8],
    lower_bytes: &[u8],
    index: usize,
    key: &str,
) -> Option<usize> {
    let key_bytes = key.as_bytes();
    if !lower_bytes[index..].starts_with(key_bytes) {
        return None;
    }
    let cursor = index + key_bytes.len();
    if cursor < bytes.len() && is_identifier_byte(bytes[cursor]) {
        return None;
    }
    Some(cursor)
}

fn cursor_after_assignment_operator(
    bytes: &[u8],
    cursor: usize,
    mode: AssignmentMode,
) -> Option<(usize, Option<u8>)> {
    let mut cursor = skip_ascii_whitespace(bytes, cursor);
    if cursor >= bytes.len() || (bytes[cursor] != b':' && bytes[cursor] != b'=') {
        return None;
    }
    cursor = skip_ascii_whitespace(bytes, cursor + 1);
    let quote = assignment_quote(bytes, &mut cursor);
    if matches!(mode, AssignmentMode::RequiredQuote) && quote.is_none() {
        return None;
    }
    Some((cursor, quote))
}

fn assignment_quote(bytes: &[u8], cursor: &mut usize) -> Option<u8> {
    if *cursor < bytes.len() && (bytes[*cursor] == b'"' || bytes[*cursor] == b'\'') {
        let quote = bytes[*cursor];
        *cursor += 1;
        Some(quote)
    } else {
        None
    }
}

fn assignment_value_end(
    bytes: &[u8],
    value_start: usize,
    quote: Option<u8>,
    value_char: fn(u8) -> bool,
) -> Option<usize> {
    let mut cursor = value_start;
    while cursor < bytes.len() && value_char(bytes[cursor]) {
        cursor += 1;
    }
    if cursor - value_start < 16 {
        return None;
    }
    if quote.is_some_and(|quote| cursor >= bytes.len() || bytes[cursor] != quote) {
        return None;
    }
    Some(cursor)
}

fn assignment_entropy_passes(value: &str, detector: Detector) -> bool {
    detector
        .entropy_threshold
        .is_none_or(|threshold| shannon_entropy(value) >= threshold)
}
