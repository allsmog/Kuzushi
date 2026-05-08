use super::*;

pub(in crate::diff_scope) fn function_or_handler_detail(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let function_like = trimmed.starts_with("function ")
        || trimmed.starts_with("async function ")
        || trimmed.starts_with("def ")
        || trimmed.starts_with("func ")
        || trimmed.starts_with("fn ")
        || trimmed.contains("=>")
        || trimmed.contains(".get(")
        || trimmed.contains(".post(")
        || trimmed.contains(".put(")
        || trimmed.contains(".delete(")
        || trimmed.contains(".patch(");
    function_like.then(|| trimmed.chars().take(160).collect())
}

pub(in crate::diff_scope) fn callees_in_line(line: &str) -> Vec<String> {
    let mut callees = BTreeSet::new();
    let bytes = line.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'(' || index == 0 {
            continue;
        }
        let mut start = index;
        while start > 0 {
            let ch = bytes[start - 1] as char;
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' {
                start -= 1;
            } else {
                break;
            }
        }
        if start == index {
            continue;
        }
        let name = line[start..index].trim_matches('.');
        if is_interesting_callee(name) {
            callees.insert(name.to_string());
        }
    }
    callees.into_iter().take(20).collect()
}

pub(in crate::diff_scope) fn is_interesting_callee(name: &str) -> bool {
    if name.len() < 2 {
        return false;
    }
    let normalized = name.rsplit('.').next().unwrap_or(name);
    !matches!(
        normalized,
        "if" | "for"
            | "while"
            | "switch"
            | "catch"
            | "return"
            | "function"
            | "fn"
            | "def"
            | "require"
            | "console"
            | "log"
    )
}
