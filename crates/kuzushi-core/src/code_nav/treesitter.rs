//! Tree-sitter backend for `list_definitions`.
//!
//! Returns `Some(Vec<DefinitionEntry>)` on a successful parse, or `None`
//! when the language isn't supported / the parse fails / the parser
//! panics. The caller (`symbol_index::list_definitions`) falls back to
//! the regex-based `scan_*` helpers when this returns `None`, so a
//! pathological input file never kills an audit.
//!
//! Per-language handling uses tree-sitter `Query`s extracting function /
//! struct / enum / trait / method declarations. Captures are reported
//! with stable kind names so the JSON tool schema callers see is
//! unchanged from the regex backend.
//!
//! Public API:
//! ```ignore
//! use kuzushi_core::code_nav::treesitter::parse_defs_treesitter;
//! let defs = parse_defs_treesitter("rust", "fn foo() {}\n");
//! ```

use std::panic::{catch_unwind, AssertUnwindSafe};

use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Parser, Query, QueryCursor};

use super::symbol_index::DefinitionEntry;

/// Top-level entry. Returns `None` for unknown languages, parse
/// failures, or panic from a brittle grammar.
pub fn parse_defs_treesitter(language: &str, body: &str) -> Option<Vec<DefinitionEntry>> {
    let result = catch_unwind(AssertUnwindSafe(|| match language {
        "c" => parse_with(tree_sitter_c::LANGUAGE.into(), body, C_QUERY, c_kind_for),
        "cpp" => parse_with(
            tree_sitter_cpp::LANGUAGE.into(),
            body,
            CPP_QUERY,
            cpp_kind_for,
        ),
        "rust" => parse_with(
            tree_sitter_rust::LANGUAGE.into(),
            body,
            RUST_QUERY,
            rust_kind_for,
        ),
        "go" => parse_with(
            tree_sitter_go::LANGUAGE.into(),
            body,
            GO_QUERY,
            go_kind_for,
        ),
        "python" => parse_with(
            tree_sitter_python::LANGUAGE.into(),
            body,
            PY_QUERY,
            py_kind_for,
        ),
        "java" => parse_with(
            tree_sitter_java::LANGUAGE.into(),
            body,
            JAVA_QUERY,
            java_kind_for,
        ),
        _ => None,
    }));
    match result {
        Ok(defs) => defs,
        Err(_) => None, // grammar panic — fall back upstream
    }
}

fn parse_with(
    language: Language,
    body: &str,
    query_text: &str,
    kind_for: fn(&str) -> &'static str,
) -> Option<Vec<DefinitionEntry>> {
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(body, None)?;
    let query = Query::new(&language, query_text).ok()?;

    let bytes = body.as_bytes();
    let mut cursor = QueryCursor::new();
    let mut out: Vec<DefinitionEntry> = Vec::new();
    let mut matches = cursor.matches(&query, tree.root_node(), bytes);

    while let Some(m) = matches.next() {
        let mut name: Option<&str> = None;
        let mut signature: Option<&str> = None;
        let mut def_capture: Option<&str> = None;
        let mut def_line: Option<u32> = None;

        for capture in m.captures {
            let capture_name = query.capture_names()[capture.index as usize];
            let node = capture.node;
            let text = match node.utf8_text(bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };
            match capture_name {
                "name" => name = Some(text),
                "signature" => {
                    signature = Some(text);
                    if def_line.is_none() {
                        def_line = Some(node.start_position().row as u32 + 1);
                    }
                }
                other => {
                    def_capture = Some(other);
                    if def_line.is_none() {
                        def_line = Some(node.start_position().row as u32 + 1);
                    }
                }
            }
        }

        if let (Some(name), Some(line)) = (name, def_line) {
            let kind = def_capture.map(kind_for).unwrap_or("function").to_string();
            let signature = signature
                .map(|s| s.lines().next().unwrap_or("").trim().to_string())
                .unwrap_or_else(|| name.to_string());
            out.push(DefinitionEntry {
                name: name.to_string(),
                kind,
                line,
                signature,
            });
        }
    }

    // Stable order: by line, then name. Tree-sitter ordering is
    // generally line-major already, but be explicit.
    out.sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.name.cmp(&b.name)));
    out.dedup_by(|a, b| a.name == b.name && a.line == b.line);
    Some(out)
}

// -- Per-language queries + kind translators --------------------------

const C_QUERY: &str = r#"
(function_definition declarator: (function_declarator declarator: (identifier) @name)) @function
(declaration declarator: (function_declarator declarator: (identifier) @name)) @function_decl
(struct_specifier name: (type_identifier) @name) @struct
(union_specifier name: (type_identifier) @name) @struct
(enum_specifier name: (type_identifier) @name) @enum
(type_definition declarator: (type_identifier) @name) @struct
(preproc_function_def name: (identifier) @name) @macro
"#;

fn c_kind_for(capture: &str) -> &'static str {
    match capture {
        "function" | "function_decl" => "function",
        "struct" => "struct",
        "enum" => "enum",
        "macro" => "macro",
        _ => "function",
    }
}

const CPP_QUERY: &str = r#"
(function_definition declarator: (function_declarator declarator: (identifier) @name)) @function
(function_definition declarator: (function_declarator declarator: (field_identifier) @name)) @method
(declaration declarator: (function_declarator declarator: (identifier) @name)) @function_decl
(struct_specifier name: (type_identifier) @name) @struct
(class_specifier name: (type_identifier) @name) @struct
(union_specifier name: (type_identifier) @name) @struct
(enum_specifier name: (type_identifier) @name) @enum
"#;

fn cpp_kind_for(capture: &str) -> &'static str {
    match capture {
        "function" | "function_decl" => "function",
        "method" => "method",
        "struct" => "struct",
        "enum" => "enum",
        _ => "function",
    }
}

const RUST_QUERY: &str = r#"
(function_item name: (identifier) @name) @function
(struct_item name: (type_identifier) @name) @struct
(enum_item name: (type_identifier) @name) @enum
(trait_item name: (type_identifier) @name) @trait
(impl_item type: (type_identifier) @name) @impl
"#;

fn rust_kind_for(capture: &str) -> &'static str {
    match capture {
        "function" => "function",
        "struct" => "struct",
        "enum" => "enum",
        "trait" => "trait",
        "impl" => "impl",
        _ => "function",
    }
}

const GO_QUERY: &str = r#"
(function_declaration name: (identifier) @name) @function
(method_declaration name: (field_identifier) @name) @method
(type_declaration (type_spec name: (type_identifier) @name)) @struct
"#;

fn go_kind_for(capture: &str) -> &'static str {
    match capture {
        "function" => "function",
        "method" => "method",
        "struct" => "struct",
        _ => "function",
    }
}

const PY_QUERY: &str = r#"
(function_definition name: (identifier) @name) @function
(class_definition name: (identifier) @name) @struct
"#;

fn py_kind_for(capture: &str) -> &'static str {
    match capture {
        "function" => "function",
        "struct" => "struct",
        _ => "function",
    }
}

const JAVA_QUERY: &str = r#"
(class_declaration name: (identifier) @name) @struct
(interface_declaration name: (identifier) @name) @trait
(method_declaration name: (identifier) @name) @method
"#;

fn java_kind_for(capture: &str) -> &'static str {
    match capture {
        "struct" => "struct",
        "trait" => "trait",
        "method" => "method",
        _ => "function",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_language_returns_none() {
        assert!(parse_defs_treesitter("brainfuck", "+++[<<.]").is_none());
    }

    #[test]
    fn parses_basic_c() {
        let body = r#"
static int foo(int x) {
    return x + 1;
}

void baz(void) {
}

#define BAR(x) ((x) + 1)

struct Quux { int a; };
"#;
        let defs = parse_defs_treesitter("c", body).unwrap();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"foo"), "missing foo: {names:?}");
        assert!(names.contains(&"baz"), "missing baz: {names:?}");
        assert!(names.contains(&"Quux"), "missing Quux: {names:?}");
        // Function-like macro should be picked up.
        assert!(names.contains(&"BAR"), "missing BAR macro: {names:?}");
    }

    #[test]
    fn parses_kernel_style_c_with_macros() {
        // Linux-kernel C: heavy macro use, attribute decorators. Regex
        // backend struggles here; tree-sitter resolves the function
        // body cleanly.
        let body = r#"
#define EXPORT_SYMBOL(x)
#define __init __attribute__((__section__(".init.text")))

static __init int kuzushi_init(void)
{
    return 0;
}
EXPORT_SYMBOL(kuzushi_init);

static inline void __attribute__((always_inline))
hot_path(struct skb *s)
{
    return;
}
"#;
        let defs = parse_defs_treesitter("c", body).unwrap();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(
            names.contains(&"kuzushi_init"),
            "tree-sitter should resolve kernel-style fn: {names:?}"
        );
        assert!(
            names.contains(&"hot_path"),
            "tree-sitter should resolve attribute-decorated fn: {names:?}"
        );
    }

    #[test]
    fn parses_basic_rust() {
        let body = r#"
pub fn foo() {}
fn private_fn(x: u32) -> u32 { x }
pub struct Bar;
enum Baz { A, B }
trait Quux { fn run(&self); }
"#;
        let defs = parse_defs_treesitter("rust", body).unwrap();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"private_fn"));
        assert!(names.contains(&"Bar"));
        assert!(names.contains(&"Baz"));
        assert!(names.contains(&"Quux"));
        let kinds: Vec<&str> = defs.iter().map(|d| d.kind.as_str()).collect();
        assert!(kinds.contains(&"struct"));
        assert!(kinds.contains(&"enum"));
        assert!(kinds.contains(&"trait"));
    }

    #[test]
    fn parses_basic_python() {
        let body = r#"
class Foo:
    def bar(self): pass
    async def baz(self): pass

def top_level():
    pass
"#;
        let defs = parse_defs_treesitter("python", body).unwrap();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"Foo"));
        assert!(names.contains(&"bar"));
        assert!(names.contains(&"baz"));
        assert!(names.contains(&"top_level"));
    }

    #[test]
    fn parses_basic_go() {
        let body = r#"
package foo

func TopLevel() {}

type Server struct {
    addr string
}

func (s *Server) Start() error {
    return nil
}
"#;
        let defs = parse_defs_treesitter("go", body).unwrap();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"TopLevel"), "{names:?}");
        assert!(names.contains(&"Server"), "{names:?}");
        assert!(names.contains(&"Start"), "{names:?}");
    }

    #[test]
    fn parses_basic_java() {
        let body = r#"
public class Foo {
    public void bar() {}
    public static int baz() { return 0; }
}

interface Quux {
    void run();
}
"#;
        let defs = parse_defs_treesitter("java", body).unwrap();
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"Foo"));
        assert!(names.contains(&"bar"));
        assert!(names.contains(&"baz"));
        assert!(names.contains(&"Quux"));
    }

    #[test]
    fn results_are_stable_ordered_by_line() {
        let body = "fn b() {}\nfn a() {}\n";
        let defs = parse_defs_treesitter("rust", body).unwrap();
        // Sorted by line, then name → b first (line 1), then a (line 2).
        assert_eq!(defs[0].name, "b");
        assert_eq!(defs[0].line, 1);
        assert_eq!(defs[1].name, "a");
        assert_eq!(defs[1].line, 2);
    }
}
