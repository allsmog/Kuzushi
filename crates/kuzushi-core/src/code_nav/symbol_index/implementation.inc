use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::canonicalise::canonicalise_within;
use super::file_io::{read_source, ReadSourceInput};
use super::ripgrep::{find_references, FindReferencesInput};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDefinitionsInput {
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefinitionEntry {
    pub name: String,
    pub kind: String, // "function" | "struct" | "enum" | "method" | "macro"
    pub line: u32,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDefinitionsOutput {
    pub file: String,
    pub language: String,
    pub definitions: Vec<DefinitionEntry>,
}

pub fn list_definitions(
    root: &Path,
    input: &ListDefinitionsInput,
) -> Result<ListDefinitionsOutput> {
    let canonical = canonicalise_within(root, &input.file)
        .with_context(|| format!("list_definitions: path {:?}", input.file))?;
    let body = fs::read_to_string(&canonical)
        .with_context(|| format!("list_definitions: could not read {}", input.file))?;

    let language = detect_language(&input.file);
    let definitions = match language.as_str() {
        "c" | "cpp" => scan_c_like(&body),
        "rust" => scan_rust(&body),
        "go" => scan_go(&body),
        "python" => scan_python(&body),
        "java" => scan_java(&body),
        _ => Vec::new(),
    };

    Ok(ListDefinitionsOutput {
        file: input.file.clone(),
        language,
        definitions,
    })
}

fn detect_language(path: &str) -> String {
    let ext = path
        .rsplit('.')
        .next()
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "c" | "h" => "c".to_string(),
        "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => "cpp".to_string(),
        "rs" => "rust".to_string(),
        "go" => "go".to_string(),
        "py" => "python".to_string(),
        "java" => "java".to_string(),
        _ => "unknown".to_string(),
    }
}

fn scan_c_like(body: &str) -> Vec<DefinitionEntry> {
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

fn scan_rust(body: &str) -> Vec<DefinitionEntry> {
    let mut out = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let t = line.trim_start();
        for kw in ["pub fn ", "fn ", "pub async fn ", "async fn "] {
            if let Some(rest) = t.strip_prefix(kw) {
                if let Some(name) = rest.split(|c: char| c == '<' || c == '(').next() {
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

fn scan_go(body: &str) -> Vec<DefinitionEntry> {
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

fn scan_python(body: &str) -> Vec<DefinitionEntry> {
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

fn scan_java(body: &str) -> Vec<DefinitionEntry> {
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

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.chars().next().is_some_and(|c| c.is_ascii_digit())
}

fn keyword_at_start(token: &str) -> bool {
    matches!(
        token,
        "if" | "for" | "while" | "switch" | "return" | "case" | "do" | "else"
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadDefinitionInput {
    pub name: String,
    /// Optional file hint to scope the search.
    #[serde(default)]
    pub hint_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadDefinitionOutput {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub kind: String,
    pub signature: String,
    pub source: String,
    /// Other candidate locations the heuristic found, in case the first
    /// pick is wrong.
    pub also_seen: Vec<DefinitionEntry>,
}

/// Best-effort `read_definition`: find the symbol via `find_references`,
/// pick the line that looks like a definition (signature ending with `{`
/// or `:`), then read a window around it.
pub fn read_definition(root: &Path, input: &ReadDefinitionInput) -> Result<ReadDefinitionOutput> {
    let symbol = input.name.trim();
    anyhow::ensure!(
        !symbol.is_empty(),
        "read_definition: name must be non-empty"
    );

    let refs = find_references(
        root,
        &FindReferencesInput {
            symbol: symbol.to_string(),
            scope: input.hint_file.clone(),
            language: None,
        },
    )?;

    let mut candidates: Vec<DefinitionEntry> = refs
        .hits
        .into_iter()
        .filter_map(|hit| {
            classify_hit(&hit.snippet, symbol)
                .map(|kind| DefinitionEntry {
                    name: symbol.to_string(),
                    kind,
                    line: hit.line,
                    signature: hit.snippet.clone(),
                })
                .map(|entry| (hit.file, entry))
        })
        .map(|(file, mut entry)| {
            entry.signature = format!("{}:{}\t{}", file, entry.line, entry.signature);
            (file, entry)
        })
        .map(|(_file, e)| e)
        .collect();

    let primary = candidates
        .pop()
        .ok_or_else(|| anyhow::anyhow!("read_definition: no definition for {symbol:?}"))?;

    // The signature was decorated with file:line — split it back so we can
    // find the file and read a window.
    let (file_line_marker, signature) = primary
        .signature
        .split_once('\t')
        .unwrap_or(("", primary.signature.as_str()));
    let (file, _line_str) = file_line_marker
        .split_once(':')
        .unwrap_or(("", file_line_marker));
    let source_window = read_source(
        root,
        &ReadSourceInput {
            file: file.to_string(),
            start_line: Some(primary.line.saturating_sub(2).max(1)),
            end_line: Some(primary.line + 30),
        },
    )?;

    Ok(ReadDefinitionOutput {
        name: symbol.to_string(),
        file: file.to_string(),
        line: primary.line,
        kind: primary.kind,
        signature: signature.to_string(),
        source: source_window.contents,
        also_seen: candidates,
    })
}

fn classify_hit(snippet: &str, symbol: &str) -> Option<String> {
    let t = snippet.trim_start();
    if !contains_symbol_call(t, symbol) {
        return classify_type_hit(t, symbol);
    }
    classify_callable_hit(t)
}

fn contains_symbol_call(snippet: &str, symbol: &str) -> bool {
    let compact = format!("{symbol}(");
    let spaced = format!("{symbol} (");
    snippet.contains(&compact) || snippet.contains(&spaced)
}

fn classify_type_hit(snippet: &str, symbol: &str) -> Option<String> {
    ["struct ", "enum ", "trait ", "class ", "type "]
        .iter()
        .any(|keyword| symbol_follows_keyword(snippet, keyword, symbol))
        .then(|| "struct".to_string())
}

fn symbol_follows_keyword(snippet: &str, keyword: &str, symbol: &str) -> bool {
    snippet
        .strip_prefix(keyword)
        .map(str::trim_start)
        .is_some_and(|rest| rest.starts_with(symbol))
}

fn classify_callable_hit(snippet: &str) -> Option<String> {
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

fn is_rust_function_signature(snippet: &str) -> bool {
    ["fn ", "pub fn ", "async fn ", "pub async fn "]
        .iter()
        .any(|prefix| snippet.starts_with(prefix))
}

fn is_python_function_signature(snippet: &str) -> bool {
    ["def ", "async def "]
        .iter()
        .any(|prefix| snippet.starts_with(prefix))
}

fn is_c_like_function_signature(snippet: &str) -> bool {
    snippet.contains(") {") || snippet.ends_with(')')
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn list_c_definitions() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "a.c",
            "static int foo(int x) {\n  return x;\n}\n\n#define BAR 1\n\nvoid baz()\n{\n}\n",
        );
        let out = list_definitions(
            tmp.path(),
            &ListDefinitionsInput {
                file: "a.c".to_string(),
            },
        )
        .unwrap();
        let names: Vec<&str> = out.definitions.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"baz"));
    }

    #[test]
    fn list_rust_definitions() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "a.rs",
            "pub fn foo() {}\nfn private_fn(x: u32) -> u32 { x }\npub struct Bar;\nenum Baz { A, B }\n",
        );
        let out = list_definitions(
            tmp.path(),
            &ListDefinitionsInput {
                file: "a.rs".to_string(),
            },
        )
        .unwrap();
        let kinds: Vec<&str> = out.definitions.iter().map(|d| d.kind.as_str()).collect();
        let names: Vec<&str> = out.definitions.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"private_fn"));
        assert!(names.contains(&"Bar"));
        assert!(names.contains(&"Baz"));
        assert!(kinds.contains(&"struct"));
        assert!(kinds.contains(&"enum"));
    }

    #[test]
    fn list_python_definitions() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "a.py",
            "class Foo:\n    def bar(self): pass\n    async def baz(self): pass\n\ndef top_level():\n    pass\n",
        );
        let out = list_definitions(
            tmp.path(),
            &ListDefinitionsInput {
                file: "a.py".to_string(),
            },
        )
        .unwrap();
        let names: Vec<&str> = out.definitions.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"Foo"));
        assert!(names.contains(&"bar"));
        assert!(names.contains(&"baz"));
        assert!(names.contains(&"top_level"));
    }

    #[test]
    fn list_go_and_java_definitions() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "a.go",
            "type Server struct{}\nfunc NewServer() *Server { return nil }\nfunc (s *Server) Serve() {}\n",
        );
        write(
            tmp.path(),
            "A.java",
            "public class A {\n  public void run() {}\n}\ninterface Worker {}\n",
        );

        let go = list_definitions(
            tmp.path(),
            &ListDefinitionsInput {
                file: "a.go".to_string(),
            },
        )
        .unwrap();
        let go_names: Vec<&str> = go.definitions.iter().map(|d| d.name.as_str()).collect();
        assert!(go_names.contains(&"Server"));
        assert!(go_names.contains(&"NewServer"));
        assert!(go_names.contains(&"Serve"));

        let java = list_definitions(
            tmp.path(),
            &ListDefinitionsInput {
                file: "A.java".to_string(),
            },
        )
        .unwrap();
        let java_names: Vec<&str> = java.definitions.iter().map(|d| d.name.as_str()).collect();
        assert!(java_names.contains(&"A"));
        assert!(java_names.contains(&"Worker"));
    }

    #[test]
    fn classify_hit_accepts_definitions_and_rejects_call_sites() {
        assert_eq!(
            classify_hit("pub async fn target() {}", "target").as_deref(),
            Some("function")
        );
        assert_eq!(
            classify_hit("async def target():", "target").as_deref(),
            Some("function")
        );
        assert_eq!(
            classify_hit("func target() {}", "target").as_deref(),
            Some("function")
        );
        assert_eq!(
            classify_hit("int target(int x)", "target").as_deref(),
            Some("function")
        );
        assert_eq!(
            classify_hit("struct target {", "target").as_deref(),
            Some("struct")
        );
        assert_eq!(classify_hit("let x = target();", "target"), None);
        assert_eq!(classify_hit("fn other() {}", "target"), None);
    }
}
