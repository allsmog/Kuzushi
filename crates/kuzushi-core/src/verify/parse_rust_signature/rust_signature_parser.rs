use super::*;

pub(crate) fn parse_rust_signature(signature: &str) -> Option<RustSignature> {
    let trimmed = signature.trim();
    // Find `fn ` token.
    let fn_start = trimmed.find("fn ")?;
    let after_fn = &trimmed[fn_start + 3..];
    // Function name: everything up to `(` or `<` (generics).
    let name_end = after_fn.find(['(', '<']).unwrap_or(after_fn.len());
    let fn_name = after_fn[..name_end].trim().to_string();
    if fn_name.is_empty()
        || !fn_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    // Find balanced argument parens.
    let arg_open = after_fn.find('(')?;
    let mut depth = 0_i32;
    let mut arg_close = None;
    for (i, ch) in after_fn[arg_open..].char_indices() {
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
    let arg_list = &after_fn[arg_open + 1..arg_close];
    let args = split_top_level_args(arg_list)
        .into_iter()
        .filter_map(|raw| extract_arg_type(&raw))
        .collect::<Vec<_>>();
    // Return type: search after the `)` for `-> ...` ending at `{` or end.
    let tail = &after_fn[arg_close + 1..];
    let return_type = tail.find("->").and_then(|arrow| {
        let after_arrow = &tail[arrow + 2..];
        let stop = after_arrow
            .find('{')
            .or_else(|| after_arrow.find(';'))
            .unwrap_or(after_arrow.len());
        let rt = after_arrow[..stop].trim().trim_end_matches("where");
        if rt.is_empty() {
            None
        } else {
            Some(rt.trim().to_string())
        }
    });
    Some(RustSignature {
        fn_name,
        args,
        return_type,
    })
}

pub(in crate::verify) fn split_top_level_args(arg_list: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut depth = 0_i32;
    for ch in arg_list.chars() {
        match ch {
            '(' | '<' | '[' => {
                depth += 1;
                current.push(ch);
            }
            ')' | '>' | ']' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                if !current.trim().is_empty() {
                    out.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_string());
    }
    out
}

pub(in crate::verify) fn extract_arg_type(raw: &str) -> Option<String> {
    // Skip self receivers entirely — methods on a type can't be
    // invoked from a free harness without constructing an instance.
    let trimmed = raw.trim();
    if trimmed == "self"
        || trimmed == "&self"
        || trimmed == "&mut self"
        || trimmed.starts_with("self:")
    {
        return None;
    }
    // Argument shape is `<pattern>: <type>`. The pattern can include
    // `mut`, attributes, tuples — we only care about the type part.
    let colon = trimmed.find(':')?;
    let ty = trimmed[colon + 1..].trim().to_string();
    Some(ty)
}
