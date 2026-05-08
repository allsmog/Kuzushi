use super::*;

pub(in crate::verify) fn extract_c_arg_type(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "void" {
        return None;
    }
    // Argument shape is `[qualifiers] <type> [*…] <name>` with optional
    // `[size]` suffix on the name. Like split_c_head, take the *type*
    // portion by stripping the trailing identifier (the parameter name)
    // and any array brackets.
    let bytes = trimmed.as_bytes();
    let mut end = bytes.len();
    // Strip trailing array brackets `[N]` if present.
    if end > 0 && bytes[end - 1] == b']' {
        if let Some(open) = trimmed.rfind('[') {
            end = open;
            while end > 0 && bytes[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
        }
    }
    let mut name_end = end;
    while name_end > 0 {
        let c = bytes[name_end - 1];
        if c.is_ascii_alphanumeric() || c == b'_' {
            name_end -= 1;
        } else {
            break;
        }
    }
    // Anonymous parameter (e.g. `int` with no name) — whole thing is the type.
    if name_end == end {
        return Some(trimmed.to_string());
    }
    // If `name_end == 0` the whole token is identifier-only — that's
    // probably a single-token type like `size_t`, no name; treat as
    // unnamed.
    if name_end == 0 {
        return Some(trimmed.to_string());
    }
    let head = trimmed[..name_end].trim();
    if head.is_empty() {
        // No type before name — malformed.
        return None;
    }
    Some(head.to_string())
}
