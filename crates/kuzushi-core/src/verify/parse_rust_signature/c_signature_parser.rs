use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CSignature {
    pub fn_name: String,
    pub args: Vec<String>,
    pub return_type: Option<String>,
}

/// Parse a C function signature like
/// `static int parse_packet(const char *p, size_t n)`. Returns `None`
/// when the input doesn't look like a callable C definition (no name,
/// or shape that would make a synthesized call ambiguous).
///
/// Limitations are intentional and match the Rust analogue: single-line
/// signatures only; multi-line `(\n  arg1,\n  arg2\n)` reconstruction
/// is the codeindex facade's job in a follow-up.
pub(crate) fn parse_c_signature(signature: &str) -> Option<CSignature> {
    let trimmed = signature.trim().trim_end_matches('{').trim();
    // Bail on obvious non-functions.
    if trimmed.is_empty()
        || trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("/*")
    {
        return None;
    }
    let arg_open = trimmed.find('(')?;
    let mut depth = 0_i32;
    let mut arg_close = None;
    for (i, ch) in trimmed[arg_open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    arg_close = Some(arg_open + i);
                    break;
                }
            }
            _ => {}
        }
    }
    let arg_close = arg_close?;

    // Extract return type + name from the head (everything up to
    // `arg_open`). We split on whitespace plus `*`/`&` and consider
    // the *last* identifier-shaped token the function name.
    let head = trimmed[..arg_open].trim();
    if head.is_empty() {
        return None;
    }
    let (return_type, fn_name) = split_c_head(head)?;

    // Reject control-flow keywords that look like calls (`if (...)`,
    // `while (...)`, `switch (...)`).
    if matches!(
        fn_name.as_str(),
        "if" | "while" | "for" | "switch" | "return" | "do" | "else" | "case" | "sizeof"
    ) {
        return None;
    }

    let arg_list = &trimmed[arg_open + 1..arg_close];
    let args = split_top_level_args(arg_list)
        .into_iter()
        .filter_map(|raw| extract_c_arg_type(&raw))
        .collect::<Vec<_>>();

    Some(CSignature {
        fn_name,
        args,
        return_type,
    })
}

/// Split the head of a C function signature into `(return_type, name)`.
/// Pointer markers (`*`) and ref markers (`&`) attach to the return
/// type. `void` return types are preserved.
pub(in crate::verify) fn split_c_head(head: &str) -> Option<(Option<String>, String)> {
    let head = head.trim();
    // Find the rightmost identifier-shaped token; everything before it
    // is the return type.
    let bytes = head.as_bytes();
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let mut start = end;
    while start > 0 {
        let c = bytes[start - 1];
        if c.is_ascii_alphanumeric() || c == b'_' {
            start -= 1;
        } else {
            break;
        }
    }
    if start == end {
        return None;
    }
    let name = head[start..end].to_string();
    if !is_identifier(&name) {
        return None;
    }
    let return_type_raw = head[..start].trim();
    let return_type = if return_type_raw.is_empty() {
        None
    } else {
        Some(return_type_raw.to_string())
    };
    Some((return_type, name))
}
