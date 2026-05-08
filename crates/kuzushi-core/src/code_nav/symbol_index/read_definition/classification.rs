pub(in crate::code_nav::symbol_index) fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.chars().next().is_some_and(|c| c.is_ascii_digit())
}

pub(in crate::code_nav::symbol_index) fn keyword_at_start(token: &str) -> bool {
    matches!(
        token,
        "if" | "for" | "while" | "switch" | "return" | "case" | "do" | "else"
    )
}

pub(in crate::code_nav::symbol_index) fn classify_hit(
    snippet: &str,
    symbol: &str,
) -> Option<String> {
    let t = snippet.trim_start();
    if !contains_symbol_call(t, symbol) {
        return classify_type_hit(t, symbol);
    }
    classify_callable_hit(t)
}

pub(super) fn contains_symbol_call(snippet: &str, symbol: &str) -> bool {
    let compact = format!("{symbol}(");
    let spaced = format!("{symbol} (");
    snippet.contains(&compact) || snippet.contains(&spaced)
}

pub(super) fn classify_type_hit(snippet: &str, symbol: &str) -> Option<String> {
    ["struct ", "enum ", "trait ", "class ", "type "]
        .iter()
        .any(|keyword| symbol_follows_keyword(snippet, keyword, symbol))
        .then(|| "struct".to_string())
}

pub(super) fn symbol_follows_keyword(snippet: &str, keyword: &str, symbol: &str) -> bool {
    snippet
        .strip_prefix(keyword)
        .map(str::trim_start)
        .is_some_and(|rest| rest.starts_with(symbol))
}

pub(super) fn classify_callable_hit(snippet: &str) -> Option<String> {
    [
        is_rust_function_signature(snippet),
        is_python_function_signature(snippet),
        snippet.starts_with("func "),
        is_c_like_function_signature(snippet),
    ]
    .into_iter()
    .any(|matched| matched)
    .then(|| "function".to_string())
}

pub(super) fn is_rust_function_signature(snippet: &str) -> bool {
    ["fn ", "pub fn ", "async fn ", "pub async fn "]
        .iter()
        .any(|prefix| snippet.starts_with(prefix))
}

pub(super) fn is_python_function_signature(snippet: &str) -> bool {
    ["def ", "async def "]
        .iter()
        .any(|prefix| snippet.starts_with(prefix))
}

pub(super) fn is_c_like_function_signature(snippet: &str) -> bool {
    snippet.contains(") {") || snippet.ends_with(')')
}
