use super::prelude::*;
use super::*;

pub(in crate::code_nav) fn scan_go(body: &str) -> Vec<DefinitionEntry> {
    let mut out = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("func ") {
            // method: `func (r *Foo) Name(...)`; function: `func Name(...)`
            let after_recv = rest.trim_start_matches('(');
            let token = if t.starts_with("func (") {
                // method
                let end = rest.find(')').unwrap_or(0);
                let after = &rest[end + 1..].trim_start();
                after.split('(').next().unwrap_or("").trim()
            } else {
                after_recv.split('(').next().unwrap_or("").trim()
            };
            if !token.is_empty() {
                let kind = if t.starts_with("func (") {
                    "method"
                } else {
                    "function"
                };
                out.push(DefinitionEntry {
                    name: token.to_string(),
                    kind: kind.to_string(),
                    line: (idx as u32) + 1,
                    signature: t.to_string(),
                });
            }
        } else if let Some(rest) = t.strip_prefix("type ") {
            if let Some(name) = rest.split_whitespace().next() {
                out.push(DefinitionEntry {
                    name: name.to_string(),
                    kind: "struct".to_string(),
                    line: (idx as u32) + 1,
                    signature: t.to_string(),
                });
            }
        }
    }
    out
}

pub(in crate::code_nav) fn scan_python(body: &str) -> Vec<DefinitionEntry> {
    let mut out = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let t = line.trim_start();
        for (kw, kind) in [
            ("def ", "function"),
            ("async def ", "function"),
            ("class ", "struct"),
        ] {
            if let Some(rest) = t.strip_prefix(kw) {
                if let Some(name) = rest.split(|c: char| c == '(' || c == ':').next() {
                    let n = name.trim();
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

pub(in crate::code_nav) fn scan_java(body: &str) -> Vec<DefinitionEntry> {
    let mut out = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let t = line.trim_start();
        for (kw, kind) in [
            ("public class ", "struct"),
            ("class ", "struct"),
            ("public interface ", "trait"),
            ("interface ", "trait"),
        ] {
            if let Some(rest) = t.strip_prefix(kw) {
                if let Some(name) = rest.split_whitespace().next() {
                    let n = name.trim_end_matches('{');
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
