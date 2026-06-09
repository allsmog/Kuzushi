use super::*;

pub(in crate::code_nav) fn scan_c_like(body: &str) -> Vec<DefinitionEntry> {
    // Match e.g. `static int foo(...)` followed by `{` on same or next line.
    // Heuristic: a line that ends with `)` after a `(` and a known type-ish
    // start. False positives on macro invocations are tolerable — the
    // model can verify with read_source.
    let mut out = Vec::new();
    let lines: Vec<&str> = body.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        // Skip preprocessor / comments quickly.
        if trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        let Some(open_paren) = trimmed.find('(') else {
            continue;
        };
        let head = &trimmed[..open_paren];
        // Function head must contain at least two whitespace-separated
        // tokens (return type + name) and end on an identifier.
        let tokens: Vec<&str> = head.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        let name = match tokens.last() {
            Some(t) => t.trim_start_matches('*').trim_start_matches('&'),
            None => continue,
        };
        if !is_ident(name) || keyword_at_start(tokens[0]) {
            continue;
        }
        // Require either `{` on the same line or the next non-empty line.
        let same = trimmed.contains('{');
        let next_open = lines
            .get(idx + 1)
            .map(|l| l.trim_start().starts_with('{'))
            .unwrap_or(false);
        if !same && !next_open {
            continue;
        }
        out.push(DefinitionEntry {
            name: name.to_string(),
            kind: "function".to_string(),
            line: (idx as u32) + 1,
            signature: trimmed.to_string(),
        });
    }
    out
}

pub(in crate::code_nav) fn scan_rust(body: &str) -> Vec<DefinitionEntry> {
    let mut out = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let t = line.trim_start();
        for kw in ["pub fn ", "fn ", "pub async fn ", "async fn "] {
            if let Some(rest) = t.strip_prefix(kw) {
                if let Some(name) = rest.split(['<', '(']).next() {
                    let n = name.trim();
                    if !n.is_empty() {
                        out.push(DefinitionEntry {
                            name: n.to_string(),
                            kind: "function".to_string(),
                            line: (idx as u32) + 1,
                            signature: t.to_string(),
                        });
                    }
                }
                break;
            }
        }
        for (kw, kind) in [
            ("pub struct ", "struct"),
            ("struct ", "struct"),
            ("pub enum ", "enum"),
            ("enum ", "enum"),
            ("pub trait ", "trait"),
            ("trait ", "trait"),
        ] {
            if let Some(rest) = t.strip_prefix(kw) {
                let stop_chars = ['<', '{', '(', ';', ' ', '\t'];
                if let Some(name) = rest.split(|c: char| stop_chars.contains(&c)).next() {
                    let n = name.trim().trim_end_matches(';');
                    if !n.is_empty() {
                        out.push(DefinitionEntry {
                            name: n.to_string(),
                            kind: kind.to_string(),
                            line: (idx as u32) + 1,
                            signature: t.to_string(),
                        });
                    }
                }
                break;
            }
        }
    }
    out
}
