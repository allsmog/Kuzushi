use super::prelude::*;
use super::*;

pub(crate) fn extract_first_quoted(value: &str) -> Option<String> {
    let mut chars = value.char_indices();
    while let Some((start, quote)) = chars.next() {
        if !matches!(quote, '"' | '\'' | '`') {
            continue;
        }
        for (offset, ch) in value[start + quote.len_utf8()..].char_indices() {
            if ch == quote {
                let end = start + quote.len_utf8() + offset;
                let candidate = &value[start + quote.len_utf8()..end];
                if !candidate.trim().is_empty() {
                    return Some(candidate.to_string());
                }
                return None;
            }
        }
    }
    None
}

pub(crate) fn python_route_methods(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let methods_index = lower.find("methods")?;
    let method_area = &lower[methods_index..];
    let mut methods = Vec::new();
    for method in ["get", "post", "put", "patch", "delete"] {
        if method_area.contains(method) {
            methods.push(method.to_ascii_uppercase());
        }
    }
    if methods.is_empty() {
        None
    } else {
        Some(methods.join(","))
    }
}
