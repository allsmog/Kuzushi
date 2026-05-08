use super::*;

/// Best-effort: read the suspect file and locate the enclosing function
/// signature for the finding's `start_line`. Returns `None` when the
/// file isn't readable or no signature is found within a small look-back
/// window. Pure-text and language-agnostic — for joern/clang accuracy
/// we'll route through `IndexFacade` in a future iteration.
pub(crate) fn extract_enclosing_function(
    file_path: &Path,
    start_line: u32,
) -> Option<EnclosingFunction> {
    let raw = std::fs::read_to_string(file_path).ok()?;
    let lines: Vec<&str> = raw.lines().collect();
    let target_idx = (start_line.saturating_sub(1) as usize).min(lines.len().saturating_sub(1));

    // Look back up to 200 lines for a likely function signature. The
    // heuristics are intentionally conservative — we only care that
    // there *is* a signature line; the harness compiles the whole file
    // verbatim and the test calls into the file by including it.
    let window_start = target_idx.saturating_sub(200);
    let mut sig_line_idx: Option<usize> = None;
    for line in (window_start..=target_idx).rev() {
        let trimmed = lines[line].trim();
        if looks_like_function_signature(trimmed) {
            sig_line_idx = Some(line);
            break;
        }
    }
    sig_line_idx.map(|idx| EnclosingFunction {
        signature: lines[idx].to_string(),
        signature_line: idx as u32 + 1,
        line: target_idx as u32 + 1,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnclosingFunction {
    pub signature: String,
    /// 1-based line number of the located function signature.
    pub signature_line: u32,
    /// 1-based line number of the suspect (i.e. the original
    /// `finding.start_line`, clamped to the file).
    pub line: u32,
}

/// Heuristic: does this line look like a function *definition* (i.e. a
/// signature attached to a body)? Accepts Rust `fn`, C/C++
/// `<type> name(...) {`, Python `def name(...):`, JS `function name(...)
/// {`. Rejects forward declarations, calls, and control-flow lines.
///
/// Definitions must end with `{` (C/Rust/JS), `:` (Python), or end with
/// a `(` with no closing paren (multi-line signature continuation —
/// caller resolves via the look-back loop).
pub(crate) fn looks_like_function_signature(trimmed: &str) -> bool {
    if is_ignorable_signature_line(trimmed) || trimmed.ends_with(';') {
        return false;
    }

    if has_function_keyword(trimmed) {
        return keyword_function_has_body_or_continuation(trimmed);
    }

    has_signature_terminator(trimmed) && is_c_like_function_header(trimmed)
}

pub(in crate::verification) fn is_ignorable_signature_line(trimmed: &str) -> bool {
    trimmed.is_empty()
        || trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
}

pub(in crate::verification) fn has_function_keyword(trimmed: &str) -> bool {
    RUST_PY_JS_FUNCTION_PREFIXES
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
        || trimmed.contains(" fn ")
}

pub(in crate::verification) fn keyword_function_has_body_or_continuation(trimmed: &str) -> bool {
    has_signature_terminator(trimmed) || trimmed.contains('{')
}

pub(in crate::verification) fn has_signature_terminator(trimmed: &str) -> bool {
    trimmed.ends_with('{')
        || trimmed.ends_with(':')
        || trimmed.ends_with('(')
        || trimmed.ends_with(',')
}

pub(in crate::verification) fn is_c_like_function_header(trimmed: &str) -> bool {
    let Some(paren) = trimmed.find('(') else {
        return false;
    };
    let head = trimmed[..paren].trim_end();
    let last_word = c_signature_last_word(head);
    let leading = c_signature_leading_word(head);

    !head.is_empty()
        && is_identifier(last_word)
        && !is_control_flow_leader(leading)
        && head.contains(char::is_whitespace)
}

pub(in crate::verification) fn c_signature_last_word(head: &str) -> &str {
    head.rsplit(c_signature_word_boundary).next().unwrap_or("")
}

pub(in crate::verification) fn c_signature_leading_word(head: &str) -> &str {
    head.split(c_signature_word_boundary).next().unwrap_or("")
}

pub(in crate::verification) fn c_signature_word_boundary(c: char) -> bool {
    c.is_whitespace() || c == '*' || c == '&'
}

pub(in crate::verification) fn is_control_flow_leader(word: &str) -> bool {
    C_CONTROL_FLOW_LEADERS.contains(&word)
}

pub(in crate::verification) fn is_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.chars().next().is_some_and(|c| c.is_ascii_digit())
}

pub(in crate::verification) const RUST_PY_JS_FUNCTION_PREFIXES: &[&str] = &[
    "fn ",
    "pub fn ",
    "def ",
    "async def ",
    "function ",
    "async function ",
    "export function ",
    "export async function ",
];

pub(in crate::verification) const C_CONTROL_FLOW_LEADERS: &[&str] = &[
    "if", "while", "for", "switch", "return", "do", "else", "case", "sizeof",
];
