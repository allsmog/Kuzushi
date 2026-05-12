//! Tree-sitter MCP tools — `node_at`, `query`, `callers`.
//!
//! Three tools the agent can invoke during a taint hunt to verify or
//! refute candidates without round-tripping a request to the model:
//!
//! * `tree_sitter:node_at`  — smallest enclosing AST node for a (file,
//!   line, column), plus its parent chain. Lets the agent ask "is this
//!   match inside a comment / string literal / call expression?"
//! * `tree_sitter:query`    — run a tree-sitter S-expression query
//!   against a file. Lets the agent ask "show me every call expression
//!   where the callee is `palloc`" or "every member access on
//!   `tidstate->tss_tidexprs`".
//! * `tree_sitter:callers`  — find every call site of a named function
//!   inside a file (cheap intra-file call graph, no resolver needed).
//!
//! Languages supported: c, cpp, javascript, typescript, python, java,
//! ruby, php, go. (Same set as `kuzushi-core::syntactic_narrowing`.)

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{Tool, ToolHandler, ToolRegistry};
use serde_json::{json, Value};
use std::path::PathBuf;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor, StreamingIterator};

pub(crate) fn build_registry() -> ToolRegistry {
    ToolRegistry::new()
        .register(node_at_descriptor(), NodeAtHandler)
        .register(query_descriptor(), QueryHandler)
        .register(callers_descriptor(), CallersHandler)
}

fn node_at_descriptor() -> Tool {
    Tool {
        name: "tree_sitter:node_at".to_string(),
        description: "Return the smallest tree-sitter AST node spanning the given byte location, plus its parent chain (kind names + byte ranges). Useful for answering 'is the match at line N inside a comment / string / call expression?'.".to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["file", "language", "line"],
            "properties": {
                "file": {"type": "string", "description": "Absolute or workspace-relative path to a source file."},
                "language": {"type": "string", "description": "Language id: c, cpp, javascript, typescript, python, java, ruby, php, or go."},
                "line": {"type": "integer", "minimum": 1, "description": "1-based line number."},
                "column": {"type": "integer", "minimum": 1, "description": "Optional 1-based column. Defaults to the first non-whitespace column on the line."}
            }
        }),
    }
}

fn query_descriptor() -> Tool {
    Tool {
        name: "tree_sitter:query".to_string(),
        description: "Run a tree-sitter S-expression query against a parsed file. Returns each match's captures with byte ranges, line/column spans, and the matched code text. Use this to find every `(call_expression function: (identifier) @fn (#eq? @fn \"palloc\"))` or similar.".to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["file", "language", "query"],
            "properties": {
                "file": {"type": "string"},
                "language": {"type": "string"},
                "query": {"type": "string", "description": "Tree-sitter S-expression query."},
                "limit": {"type": "integer", "minimum": 1, "default": 100, "description": "Cap matches returned (default 100). The agent should narrow its query rather than raise this."}
            }
        }),
    }
}

fn callers_descriptor() -> Tool {
    Tool {
        name: "tree_sitter:callers".to_string(),
        description: "List every call site of a named function inside one file. Returns line numbers, column ranges, and the line text. Cheap intra-file call graph — no name resolution across imports.".to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["file", "language", "function"],
            "properties": {
                "file": {"type": "string"},
                "language": {"type": "string"},
                "function": {"type": "string", "description": "Exact function/identifier name to match in callee position (e.g. `palloc`, `strcpy`, `req.query`)."}
            }
        }),
    }
}

struct NodeAtHandler;
struct QueryHandler;
struct CallersHandler;

#[async_trait]
impl ToolHandler for NodeAtHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let request = NodeAtRequest::from_json(&args)?;
        let parsed = parse_source_file(&request.file, &request.language)?;
        let target = node_target_byte(&parsed.bytes, request.line, request.column)?;

        let Some(node) = parsed
            .tree
            .root_node()
            .descendant_for_byte_range(target.byte, target.byte)
        else {
            return Ok(json!({
                "found": false,
                "reason": "tree-sitter could not resolve a node at the requested byte"
            }));
        };

        let chain = node_parent_chain(node, &parsed.bytes);
        Ok(json!({
            "found": true,
            "file": request.file.display().to_string(),
            "line": request.line,
            "column": target.column + 1,
            "node": chain.first().cloned().unwrap_or(Value::Null),
            "parents": chain.into_iter().skip(1).collect::<Vec<_>>(),
        }))
    }
}

#[async_trait]
impl ToolHandler for QueryHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let request = QueryRequest::from_json(&args)?;
        let parsed = parse_source_file(&request.file, &request.language)?;
        let query = Query::new(&parsed.language, &request.query)
            .with_context(|| format!("invalid tree-sitter query: {}", request.query))?;
        let out = collect_query_matches(&query, &parsed, request.limit);
        Ok(json!({
            "file": request.file.display().to_string(),
            "language": request.language,
            "query": request.query,
            "match_count": out.len(),
            "matches": out,
        }))
    }
}

#[async_trait]
impl ToolHandler for CallersHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let request = CallersRequest::from_json(&args)?;
        let parsed = parse_source_file(&request.file, &request.language)?;
        let pattern = callers_pattern(&request.language);
        let query = Query::new(&parsed.language, &pattern)
            .with_context(|| format!("could not build callers query for {}", request.language))?;
        let hits = collect_call_sites(&query, &parsed, &request.function);
        Ok(json!({
            "file": request.file.display().to_string(),
            "function": request.function,
            "hits": hits,
        }))
    }
}

struct ParsedSource {
    bytes: Vec<u8>,
    language: Language,
    tree: tree_sitter::Tree,
}

fn parse_source_file(file: &PathBuf, language_name: &str) -> Result<ParsedSource> {
    let bytes =
        std::fs::read(file).with_context(|| format!("could not read {}", file.display()))?;
    let language = grammar_for(language_name)?;
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .context("could not set tree-sitter language")?;
    let tree = parser
        .parse(&bytes, None)
        .context("tree-sitter parse failed")?;
    Ok(ParsedSource {
        bytes,
        language,
        tree,
    })
}

struct NodeTarget {
    byte: usize,
    column: usize,
}

fn node_target_byte(bytes: &[u8], line: usize, column: Option<usize>) -> Result<NodeTarget> {
    let line_start = nth_line_start(bytes, line.saturating_sub(1))
        .context("requested line is past end of file")?;
    let column = column
        .map(|c| c.saturating_sub(1))
        .unwrap_or_else(|| first_non_whitespace_column(bytes, line_start));
    Ok(NodeTarget {
        byte: (line_start + column).min(bytes.len()),
        column,
    })
}

fn node_parent_chain(node: Node<'_>, bytes: &[u8]) -> Vec<Value> {
    let mut chain = Vec::new();
    let mut cursor = node;
    loop {
        chain.push(node_summary(&cursor, bytes));
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => return chain,
        }
    }
}

fn collect_query_matches(query: &Query, parsed: &ParsedSource, limit: usize) -> Vec<Value> {
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, parsed.tree.root_node(), parsed.bytes.as_slice());
    let mut out = Vec::new();
    while let Some(query_match) = matches.next() {
        if out.len() >= limit {
            break;
        }
        let captures: Vec<Value> = query_match
            .captures
            .iter()
            .map(|capture| {
                let name = query.capture_names()[capture.index as usize].to_string();
                json!({
                    "name": name,
                    "node": node_summary(&capture.node, &parsed.bytes),
                })
            })
            .collect();
        out.push(json!({"captures": captures}));
    }
    out
}

fn collect_call_sites(query: &Query, parsed: &ParsedSource, function: &str) -> Vec<Value> {
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, parsed.tree.root_node(), parsed.bytes.as_slice());
    let mut hits = Vec::new();
    while let Some(query_match) = matches.next() {
        collect_call_site_match(
            query,
            &parsed.bytes,
            function,
            query_match.captures,
            &mut hits,
        );
    }
    hits
}

fn collect_call_site_match(
    query: &Query,
    bytes: &[u8],
    function: &str,
    captures: &[tree_sitter::QueryCapture<'_>],
    hits: &mut Vec<Value>,
) {
    for capture in captures {
        let name = query.capture_names()[capture.index as usize];
        if name != "callee" {
            continue;
        }
        collect_call_site_capture(bytes, function, captures, capture, hits);
    }
}

fn collect_call_site_capture(
    bytes: &[u8],
    function: &str,
    captures: &[tree_sitter::QueryCapture<'_>],
    capture: &tree_sitter::QueryCapture<'_>,
    hits: &mut Vec<Value>,
) {
    let captured_text = capture.node.utf8_text(bytes).unwrap_or("").to_string();
    if !callee_matches(&captured_text, function) {
        return;
    }
    let call_node = capture
        .node
        .parent()
        .or_else(|| captures.first().map(|c| c.node))
        .unwrap_or(capture.node);
    hits.push(json!({
        "callee": captured_text,
        "call": node_summary(&call_node, bytes),
    }));
}

struct NodeAtRequest {
    file: PathBuf,
    language: String,
    line: usize,
    column: Option<usize>,
}

impl NodeAtRequest {
    fn from_json(args: &Value) -> Result<Self> {
        Ok(Self {
            file: PathBuf::from(read_required_string(args, "file")?),
            language: read_required_string(args, "language")?,
            line: read_required_u64(args, "line")? as usize,
            column: args
                .get("column")
                .and_then(Value::as_u64)
                .map(|v| v as usize),
        })
    }
}

struct QueryRequest {
    file: PathBuf,
    language: String,
    query: String,
    limit: usize,
}

impl QueryRequest {
    fn from_json(args: &Value) -> Result<Self> {
        Ok(Self {
            file: PathBuf::from(read_required_string(args, "file")?),
            language: read_required_string(args, "language")?,
            query: read_required_string(args, "query")?,
            limit: args
                .get("limit")
                .and_then(Value::as_u64)
                .map(|v| v as usize)
                .unwrap_or(100),
        })
    }
}

struct CallersRequest {
    file: PathBuf,
    language: String,
    function: String,
}

impl CallersRequest {
    fn from_json(args: &Value) -> Result<Self> {
        Ok(Self {
            file: PathBuf::from(read_required_string(args, "file")?),
            language: read_required_string(args, "language")?,
            function: read_required_string(args, "function")?,
        })
    }
}

fn read_required_string(args: &Value, field: &str) -> Result<String> {
    args.get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .with_context(|| format!("missing required string field `{field}`"))
}

fn read_required_u64(args: &Value, field: &str) -> Result<u64> {
    args.get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing required integer field `{field}`"))
}

fn grammar_for(language: &str) -> Result<Language> {
    Ok(match language {
        "c" | "cpp" => tree_sitter_c::LANGUAGE.into(),
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        other => anyhow::bail!(
            "unsupported language `{other}`; supported: c, cpp, javascript, typescript, python, java, ruby, php, go"
        ),
    })
}

fn callers_pattern(language: &str) -> String {
    // Capture the callee identifier of every call expression. The
    // grammar names differ a bit per language; this covers the usual
    // ones. Languages we don't have a precise pattern for fall back to
    // a permissive `(call _) @callee` shape.
    callers_pattern_table()
        .iter()
        .find_map(|(languages, pattern)| languages.contains(&language).then_some(*pattern))
        .unwrap_or("(_) @callee")
        .to_string()
}

fn callers_pattern_table() -> &'static [(&'static [&'static str], &'static str)] {
    &[
        (
            &["javascript", "typescript"],
            "(call_expression function: (_) @callee)",
        ),
        (&["python"], "(call function: (_) @callee)"),
        (&["c", "cpp"], "(call_expression function: (_) @callee)"),
        (&["java"], "(method_invocation name: (identifier) @callee)"),
        (&["ruby"], "(call method: (identifier) @callee)"),
        (&["php"], "(function_call_expression function: (_) @callee)"),
        (&["go"], "(call_expression function: (_) @callee)"),
    ]
}

fn callee_matches(captured: &str, target: &str) -> bool {
    let captured_normalized = captured.replace([' ', '\n', '\t'], "");
    let target = target.trim();
    captured_normalized == target
        || captured_normalized.ends_with(&format!(".{target}"))
        || captured_normalized.ends_with(&format!("->{target}"))
        || captured_normalized.ends_with(&format!("::{target}"))
}

fn node_summary(node: &Node<'_>, source: &[u8]) -> Value {
    let start = node.start_position();
    let end = node.end_position();
    let snippet = node
        .utf8_text(source)
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .chars()
        .take(160)
        .collect::<String>();
    json!({
        "kind": node.kind(),
        "byte_range": [node.start_byte(), node.end_byte()],
        "start": {"row": start.row + 1, "column": start.column + 1},
        "end": {"row": end.row + 1, "column": end.column + 1},
        "snippet": snippet,
    })
}

fn nth_line_start(bytes: &[u8], line_index: usize) -> Option<usize> {
    if line_index == 0 {
        return Some(0);
    }
    let mut newlines_seen = 0;
    for (offset, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            newlines_seen += 1;
            if newlines_seen == line_index {
                return Some(offset + 1);
            }
        }
    }
    None
}

fn first_non_whitespace_column(bytes: &[u8], line_start: usize) -> usize {
    let mut column = 0;
    for &byte in bytes.iter().skip(line_start) {
        if byte == b'\n' {
            return 0;
        }
        if !byte.is_ascii_whitespace() {
            return column;
        }
        column += 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn write_temp(content: &str, suffix: &str) -> NamedTempFile {
        let file = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
        std::fs::write(file.path(), content).unwrap();
        file
    }

    #[tokio::test]
    async fn node_at_locates_a_call_expression() {
        let src = "function main() {\n    db.query(req.query.id);\n}\n";
        let file = write_temp(src, ".js");
        let resp = NodeAtHandler
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "javascript",
                "line": 2
            }))
            .await
            .unwrap();
        assert_eq!(resp["found"], json!(true));
        // Smallest node on a non-whitespace column should be inside the
        // statement body — at minimum a non-program kind.
        assert_ne!(resp["node"]["kind"].as_str(), Some("program"));
    }

    #[tokio::test]
    async fn query_returns_call_expressions_matching_a_pattern() {
        let src = "int main(void) {\n    palloc(8);\n    repalloc(p, 16);\n    return 0;\n}\n";
        let file = write_temp(src, ".c");
        let resp = QueryHandler
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "c",
                "query": "(call_expression function: (identifier) @fn (#eq? @fn \"palloc\"))"
            }))
            .await
            .unwrap();
        assert_eq!(resp["match_count"], json!(1));
    }

    #[tokio::test]
    async fn callers_finds_named_function_invocations_only() {
        let src = "int main(void) {\n    palloc(8);\n    repalloc(p, 16);\n    palloc(16);\n}\n";
        let file = write_temp(src, ".c");
        let resp = CallersHandler
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "c",
                "function": "palloc"
            }))
            .await
            .unwrap();
        let hits = resp["hits"].as_array().unwrap();
        // 2 hits for palloc, 0 for repalloc
        assert_eq!(hits.len(), 2);
        assert!(hits.iter().all(|h| h["callee"] == json!("palloc")));
    }

    #[tokio::test]
    async fn unsupported_language_returns_a_clear_error() {
        let file = write_temp("x = 1", ".rs");
        let err = NodeAtHandler
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "rust",
                "line": 1
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unsupported language"));
    }
}
