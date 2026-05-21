pub(crate) fn extract_first_quoted(value: &str) -> Option<String> {
    for (start, quote) in value.char_indices() {
        if quoted_delimiter(quote) {
            return quoted_text_after(value, start, quote);
        }
    }
    None
}

fn quoted_delimiter(ch: char) -> bool {
    matches!(ch, '"' | '\'' | '`')
}

fn quoted_text_after(value: &str, start: usize, quote: char) -> Option<String> {
    let offset_start = start + quote.len_utf8();
    for (offset, ch) in value[offset_start..].char_indices() {
        if ch == quote {
            return nonempty_quoted_text(&value[offset_start..offset_start + offset]);
        }
    }
    None
}

fn nonempty_quoted_text(candidate: &str) -> Option<String> {
    (!candidate.trim().is_empty()).then(|| candidate.to_string())
}

pub(crate) fn python_route_methods(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let methods_index = lower.find("methods")?;
    let method_area = &lower[methods_index..];
    let methods = python_http_methods()
        .iter()
        .filter(|method| method_area.contains(**method))
        .map(|method| method.to_ascii_uppercase())
        .collect::<Vec<_>>();
    nonempty_method_list(methods)
}

fn python_http_methods() -> &'static [&'static str] {
    &["get", "post", "put", "patch", "delete", "options", "head"]
}

fn nonempty_method_list(methods: Vec<String>) -> Option<String> {
    (!methods.is_empty()).then(|| methods.join(","))
}
