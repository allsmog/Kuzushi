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
//! Languages supported: see `kuzushi_mcp_treesitter::SUPPORTED_LANGUAGES`
//! (c, cpp, go, java, javascript, php, python, ruby, rust, typescript).
//! There is no permissive fallback — an unsupported language id is a hard
//! error, not a best-effort parse.

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{
    BoundedReadFile, ReadFileIdentity, ReadRootCapability, Tool, ToolHandler, ToolRegistry,
};
use kuzushi_mcp_treesitter::supported_language_list;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tree_sitter::{
    Language, Node, Parser, Query, QueryCursor, QueryCursorOptions, QueryCursorState,
    StreamingIterator,
};

const MAX_SOURCE_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_FILE_PATH_BYTES: usize = 16 * 1024;
const MAX_LANGUAGE_BYTES: usize = 32;
const MAX_QUERY_BYTES: usize = 64 * 1024;
const MAX_FUNCTION_BYTES: usize = 1024;
const MAX_POSITION_INPUT: usize = MAX_SOURCE_FILE_BYTES + 1;
const DEFAULT_QUERY_RESULT_LIMIT: usize = 100;
const MAX_QUERY_RESULT_LIMIT: usize = 500;
const MAX_CALLER_RESULT_LIMIT: usize = 500;
const MAX_QUERY_PATTERNS: usize = 128;
const MAX_QUERY_CAPTURE_NAMES: usize = 64;
const MAX_QUERY_CAPTURE_REFERENCES: usize = 64;
const MAX_CURSOR_MATCHES: usize = 10_000;
const MAX_CURSOR_PROGRESS_CALLBACKS: usize = 100_000;
const MAX_IN_PROGRESS_MATCHES: u32 = 4096;
const MAX_CAPTURES_PER_MATCH: usize = 64;
const MAX_AGGREGATE_CAPTURES: usize = 2048;
const MAX_PARENT_CHAIN_NODES: usize = 64;
const MAX_SNIPPET_BYTES: usize = 256;
const MAX_TOOL_RESPONSE_BYTES: usize = 256 * 1024;
const PARSED_SOURCE_CACHE_CAPACITY: usize = 16;

pub(crate) fn build_registry() -> Result<ToolRegistry> {
    Ok(build_registry_with_capability(
        ReadRootCapability::from_environment()?,
    ))
}

fn build_registry_with_capability(read_capability: ReadRootCapability) -> ToolRegistry {
    let context = TreeSitterContext::new(read_capability);
    ToolRegistry::new()
        .register(node_at_descriptor(), NodeAtHandler(context.clone()))
        .register(query_descriptor(), QueryHandler(context.clone()))
        .register(callers_descriptor(), CallersHandler(context))
}

fn language_schema_description() -> String {
    format!("Language id, one of: {}.", supported_language_list())
}

fn node_at_descriptor() -> Tool {
    Tool {
        name: "tree_sitter:node_at".to_string(),
        description: "Return the smallest tree-sitter AST node spanning the given byte location, plus its parent chain (kind names + byte ranges). Useful for answering 'is the match at line N inside a comment / string / call expression?'.".to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["file", "language", "line"],
            "additionalProperties": false,
            "properties": {
                "file": {"type": "string", "minLength": 1, "maxLength": MAX_FILE_PATH_BYTES, "description": "Absolute or workspace-relative path to a source file."},
                "language": {"type": "string", "minLength": 1, "maxLength": MAX_LANGUAGE_BYTES, "description": language_schema_description()},
                "line": {"type": "integer", "minimum": 1, "maximum": MAX_POSITION_INPUT, "description": "1-based line number."},
                "column": {"type": "integer", "minimum": 1, "maximum": MAX_POSITION_INPUT, "description": "Optional 1-based byte column. Defaults to the first non-whitespace column on the line."}
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
            "additionalProperties": false,
            "properties": {
                "file": {"type": "string", "minLength": 1, "maxLength": MAX_FILE_PATH_BYTES},
                "language": {"type": "string", "minLength": 1, "maxLength": MAX_LANGUAGE_BYTES, "description": language_schema_description()},
                "query": {"type": "string", "minLength": 1, "maxLength": MAX_QUERY_BYTES, "description": "Tree-sitter S-expression query."},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_QUERY_RESULT_LIMIT, "default": DEFAULT_QUERY_RESULT_LIMIT, "description": "Cap matches returned (default 100). The agent should narrow its query rather than raise this."}
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
            "additionalProperties": false,
            "properties": {
                "file": {"type": "string", "minLength": 1, "maxLength": MAX_FILE_PATH_BYTES},
                "language": {"type": "string", "minLength": 1, "maxLength": MAX_LANGUAGE_BYTES, "description": language_schema_description()},
                "function": {"type": "string", "minLength": 1, "maxLength": MAX_FUNCTION_BYTES, "description": "Exact function/identifier name to match in callee position (e.g. `palloc`, `strcpy`, `req.query`)."}
            }
        }),
    }
}

struct NodeAtHandler(TreeSitterContext);
struct QueryHandler(TreeSitterContext);
struct CallersHandler(TreeSitterContext);

#[derive(Default)]
struct Truncation {
    reasons: Vec<&'static str>,
}

impl Truncation {
    fn mark(&mut self, reason: &'static str) {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    fn is_truncated(&self) -> bool {
        !self.reasons.is_empty()
    }
}

#[async_trait]
impl ToolHandler for NodeAtHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let request = NodeAtRequest::from_json(&args)?;
        let parsed = parse_source_file(&self.0, &request.file, &request.language)?;
        let target = node_target_byte(&parsed.bytes, request.line, request.column)?;

        let Some(node) = parsed
            .tree
            .root_node()
            .descendant_for_byte_range(target.byte, target.byte)
        else {
            return bounded_tool_response(
                json!({
                    "found": false,
                    "reason": "tree-sitter could not resolve a node at the requested byte",
                    "truncated": false,
                    "truncation_reasons": [],
                }),
                "parents",
                None,
            );
        };

        let chain = node_parent_chain(node, &parsed.bytes);
        let response = json!({
            "found": true,
            "file": parsed.path.display().to_string(),
            "line": request.line,
            "column": target.display_column()?,
            "node": chain.nodes.first().cloned().unwrap_or(Value::Null),
            "parents": chain.nodes.into_iter().skip(1).collect::<Vec<_>>(),
            "truncated": chain.truncation.is_truncated(),
            "truncation_reasons": chain.truncation.reasons,
            "limits": {
                "parent_chain_nodes": MAX_PARENT_CHAIN_NODES,
                "snippet_bytes": MAX_SNIPPET_BYTES,
                "response_bytes": MAX_TOOL_RESPONSE_BYTES,
            },
        });
        bounded_tool_response(response, "parents", None)
    }
}

#[async_trait]
impl ToolHandler for QueryHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let request = QueryRequest::from_json(&args)?;
        validate_query_text_budget(&request.query)?;
        let parsed = parse_source_file(&self.0, &request.file, &request.language)?;
        let query =
            Query::new(&parsed.language, &request.query).context("invalid tree-sitter query")?;
        validate_query_budget(&query)?;
        let outcome = collect_query_matches(&query, &parsed, request.limit);
        let response = json!({
            "file": parsed.path.display().to_string(),
            "language": request.language,
            "query": request.query,
            "match_count": outcome.matches.len(),
            "examined_match_count": outcome.examined_matches,
            "capture_count": outcome.capture_count,
            "matches": outcome.matches,
            "truncated": outcome.truncation.is_truncated(),
            "truncation_reasons": outcome.truncation.reasons,
            "limits": {
                "matches": request.limit,
                "cursor_matches": MAX_CURSOR_MATCHES,
                "captures_per_match": MAX_CAPTURES_PER_MATCH,
                "aggregate_captures": MAX_AGGREGATE_CAPTURES,
                "response_bytes": MAX_TOOL_RESPONSE_BYTES,
            },
        });
        bounded_tool_response(response, "matches", Some("match_count"))
    }
}

#[async_trait]
impl ToolHandler for CallersHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let request = CallersRequest::from_json(&args)?;
        let parsed = parse_source_file(&self.0, &request.file, &request.language)?;
        let pattern = callers_pattern(&request.language)?;
        let query = Query::new(&parsed.language, pattern)
            .with_context(|| format!("could not build callers query for {}", request.language))?;
        let outcome = collect_call_sites(&query, &parsed, &request.function);
        let response = json!({
            "file": parsed.path.display().to_string(),
            "function": request.function,
            "hit_count": outcome.hits.len(),
            "examined_match_count": outcome.examined_matches,
            "hits": outcome.hits,
            "truncated": outcome.truncation.is_truncated(),
            "truncation_reasons": outcome.truncation.reasons,
            "limits": {
                "hits": MAX_CALLER_RESULT_LIMIT,
                "cursor_matches": MAX_CURSOR_MATCHES,
                "captures_per_match": MAX_CAPTURES_PER_MATCH,
                "aggregate_captures": MAX_AGGREGATE_CAPTURES,
                "response_bytes": MAX_TOOL_RESPONSE_BYTES,
            },
        });
        bounded_tool_response(response, "hits", Some("hit_count"))
    }
}

#[derive(Clone)]
struct TreeSitterContext {
    read_capability: ReadRootCapability,
    cache: ParsedSourceCache,
}

impl TreeSitterContext {
    fn new(read_capability: ReadRootCapability) -> Self {
        Self {
            read_capability,
            cache: ParsedSourceCache::default(),
        }
    }
}

struct ParsedSource {
    path: PathBuf,
    bytes: Vec<u8>,
    language: Language,
    tree: tree_sitter::Tree,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct SourceCacheKey {
    path: PathBuf,
    language: String,
    identity: ReadFileIdentity,
}

#[derive(Clone, Default)]
struct ParsedSourceCache(Arc<Mutex<ParsedSourceCacheState>>);

#[derive(Default)]
struct ParsedSourceCacheState {
    entries: HashMap<SourceCacheKey, Arc<ParsedSource>>,
    recency: VecDeque<SourceCacheKey>,
}

impl ParsedSourceCache {
    fn get(&self, key: &SourceCacheKey) -> Option<Arc<ParsedSource>> {
        let mut state = self.0.lock().ok()?;
        let parsed = state.entries.get(key).cloned()?;
        touch_cache_key(&mut state.recency, key);
        Some(parsed)
    }

    fn insert(&self, key: SourceCacheKey, parsed: Arc<ParsedSource>) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        remove_stale_cache_entries(&mut state, &key);
        state.entries.insert(key.clone(), parsed);
        touch_cache_key(&mut state.recency, &key);
        evict_cache_overflow(&mut state);
    }
}

fn touch_cache_key(recency: &mut VecDeque<SourceCacheKey>, key: &SourceCacheKey) {
    recency.retain(|candidate| candidate != key);
    recency.push_back(key.clone());
}

fn remove_stale_cache_entries(state: &mut ParsedSourceCacheState, current: &SourceCacheKey) {
    state.entries.retain(|key, _| {
        key.path != current.path || key.language != current.language || key == current
    });
    state.recency.retain(|key| state.entries.contains_key(key));
}

fn evict_cache_overflow(state: &mut ParsedSourceCacheState) {
    while state.entries.len() > PARSED_SOURCE_CACHE_CAPACITY {
        if let Some(oldest) = state.recency.pop_front() {
            state.entries.remove(&oldest);
        }
    }
}

fn parse_source_file(
    context: &TreeSitterContext,
    file: &Path,
    language_name: &str,
) -> Result<Arc<ParsedSource>> {
    let opened = context.read_capability.open(file, MAX_SOURCE_FILE_BYTES)?;
    let provisional_key = SourceCacheKey {
        path: opened.path().to_path_buf(),
        language: language_name.to_string(),
        identity: opened.identity().clone(),
    };
    if let Some(parsed) = verified_metadata_cache_hit(context, &opened, &provisional_key)? {
        return Ok(parsed);
    }
    let (bytes, identity) = opened.read_bytes_with_identity()?;
    let key = SourceCacheKey {
        identity,
        ..provisional_key
    };
    if let Some(parsed) = context.cache.get(&key) {
        return Ok(parsed);
    }
    let (language, tree) = parse_source_bytes(&bytes, language_name)?;
    let parsed = Arc::new(ParsedSource {
        path: key.path.clone(),
        bytes,
        language,
        tree,
    });
    context.cache.insert(key, Arc::clone(&parsed));
    Ok(parsed)
}

fn verified_metadata_cache_hit(
    context: &TreeSitterContext,
    opened: &BoundedReadFile,
    key: &SourceCacheKey,
) -> Result<Option<Arc<ParsedSource>>> {
    if key.identity.requires_content_digest() {
        return Ok(None);
    }
    let Some(parsed) = context.cache.get(key) else {
        return Ok(None);
    };
    opened.verify_unchanged()?;
    Ok(Some(parsed))
}

fn parse_source_bytes(bytes: &[u8], language_name: &str) -> Result<(Language, tree_sitter::Tree)> {
    let language = grammar_for(language_name)?;
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .context("could not set tree-sitter language")?;
    let tree = parser
        .parse(bytes, None)
        .context("tree-sitter parse failed")?;
    Ok((language, tree))
}

struct NodeTarget {
    byte: usize,
    column: usize,
}

impl NodeTarget {
    fn display_column(&self) -> Result<usize> {
        self.column
            .checked_add(1)
            .context("requested column could not be represented")
    }
}

fn node_target_byte(bytes: &[u8], line: usize, column: Option<usize>) -> Result<NodeTarget> {
    let line_index = line
        .checked_sub(1)
        .context("line must be a positive 1-based integer")?;
    let line_start =
        nth_line_start(bytes, line_index).context("requested line is past end of file")?;
    let line_end = line_end(bytes, line_start)?;
    let column = requested_column(bytes, line_start, column)?;
    let line_bytes = line_end
        .checked_sub(line_start)
        .context("source line bounds are invalid")?;
    if column > line_bytes {
        anyhow::bail!("requested column is past end of line");
    }
    let byte = line_start
        .checked_add(column)
        .filter(|offset| *offset <= bytes.len())
        .context("requested source position is outside the file")?;
    Ok(NodeTarget { byte, column })
}

fn line_end(bytes: &[u8], line_start: usize) -> Result<usize> {
    let line = bytes
        .get(line_start..)
        .context("source line start is outside the file")?;
    let Some(relative_end) = line.iter().position(|byte| *byte == b'\n') else {
        return Ok(bytes.len());
    };
    line_start
        .checked_add(relative_end)
        .context("source line end overflowed")
}

fn requested_column(bytes: &[u8], line_start: usize, column: Option<usize>) -> Result<usize> {
    match column {
        Some(column) => column
            .checked_sub(1)
            .context("column must be a positive 1-based integer"),
        None => Ok(first_non_whitespace_column(bytes, line_start)),
    }
}

struct ParentChain {
    nodes: Vec<Value>,
    truncation: Truncation,
}

fn node_parent_chain(node: Node<'_>, bytes: &[u8]) -> ParentChain {
    let mut nodes = Vec::new();
    let mut truncation = Truncation::default();
    let mut cursor = node;
    loop {
        nodes.push(node_summary(&cursor, bytes));
        match cursor.parent() {
            Some(parent) => cursor = parent,
            None => break,
        }
        if nodes.len() >= MAX_PARENT_CHAIN_NODES {
            truncation.mark("parent_chain_limit");
            break;
        }
    }
    ParentChain { nodes, truncation }
}

struct QueryOutcome {
    matches: Vec<Value>,
    examined_matches: usize,
    capture_count: usize,
    truncation: Truncation,
}

struct CallersOutcome {
    hits: Vec<Value>,
    examined_matches: usize,
    truncation: Truncation,
}

#[derive(Default)]
struct CursorBudget {
    examined_matches: usize,
    capture_count: usize,
    truncation: Truncation,
}

impl CursorBudget {
    fn begin_match(&mut self) -> bool {
        if self.examined_matches >= MAX_CURSOR_MATCHES {
            self.truncation.mark("cursor_match_limit");
            return false;
        }
        self.examined_matches = self.examined_matches.saturating_add(1);
        true
    }

    fn accept_result(&mut self, result_count: usize, limit: usize) -> bool {
        if result_count < limit {
            return true;
        }
        self.truncation.mark("result_limit");
        false
    }

    fn capture_allowance(&mut self, requested: usize) -> usize {
        let remaining = MAX_AGGREGATE_CAPTURES.saturating_sub(self.capture_count);
        let allowed = requested.min(MAX_CAPTURES_PER_MATCH).min(remaining);
        self.mark_capture_truncation(requested, remaining);
        self.capture_count = self.capture_count.saturating_add(allowed);
        allowed
    }

    fn mark_capture_truncation(&mut self, requested: usize, remaining: usize) {
        if requested > MAX_CAPTURES_PER_MATCH {
            self.truncation.mark("captures_per_match_limit");
        }
        if requested > remaining {
            self.truncation.mark("aggregate_capture_limit");
        }
    }
}

fn collect_query_matches(query: &Query, parsed: &ParsedSource, limit: usize) -> QueryOutcome {
    let mut cursor = bounded_query_cursor();
    let mut progress = QueryProgress::default();
    let (matches, mut budget) =
        scan_query_matches(query, parsed, limit, &mut cursor, &mut progress);
    finish_cursor_budget(&mut budget, &cursor, progress.exhausted);
    QueryOutcome {
        matches,
        examined_matches: budget.examined_matches,
        capture_count: budget.capture_count,
        truncation: budget.truncation,
    }
}

fn scan_query_matches(
    query: &Query,
    parsed: &ParsedSource,
    limit: usize,
    cursor: &mut QueryCursor,
    progress: &mut QueryProgress,
) -> (Vec<Value>, CursorBudget) {
    let mut callback = |_: &QueryCursorState| progress.observe();
    let options = QueryCursorOptions::new().progress_callback(&mut callback);
    let mut stream = cursor.matches_with_options(
        query,
        parsed.tree.root_node(),
        parsed.bytes.as_slice(),
        options,
    );
    let mut out = Vec::new();
    let mut budget = CursorBudget::default();
    while let Some(query_match) = stream.next() {
        let Some(value) = prepare_query_match(
            query,
            parsed,
            query_match.captures,
            &mut budget,
            out.len(),
            limit,
        ) else {
            break;
        };
        out.push(value);
    }
    (out, budget)
}

fn prepare_query_match(
    query: &Query,
    parsed: &ParsedSource,
    captures: &[tree_sitter::QueryCapture<'_>],
    budget: &mut CursorBudget,
    result_count: usize,
    limit: usize,
) -> Option<Value> {
    if !budget.begin_match() || !budget.accept_result(result_count, limit) {
        return None;
    }
    bounded_query_match(query, parsed, captures, budget)
}

fn bounded_query_match(
    query: &Query,
    parsed: &ParsedSource,
    captures: &[tree_sitter::QueryCapture<'_>],
    budget: &mut CursorBudget,
) -> Option<Value> {
    let allowance = budget.capture_allowance(captures.len());
    if allowance == 0 && !captures.is_empty() {
        return None;
    }
    let values = captures
        .iter()
        .take(allowance)
        .filter_map(|capture| query_capture_value(query, parsed, capture))
        .collect::<Vec<_>>();
    Some(json!({"captures": values}))
}

fn query_capture_value(
    query: &Query,
    parsed: &ParsedSource,
    capture: &tree_sitter::QueryCapture<'_>,
) -> Option<Value> {
    let index = usize::try_from(capture.index).ok()?;
    let name = query.capture_names().get(index)?;
    Some(json!({
        "name": name,
        "node": node_summary(&capture.node, &parsed.bytes),
    }))
}

fn collect_call_sites(query: &Query, parsed: &ParsedSource, function: &str) -> CallersOutcome {
    let mut cursor = bounded_query_cursor();
    let mut progress = QueryProgress::default();
    let (hits, mut budget) = scan_call_sites(query, parsed, function, &mut cursor, &mut progress);
    finish_cursor_budget(&mut budget, &cursor, progress.exhausted);
    CallersOutcome {
        hits,
        examined_matches: budget.examined_matches,
        truncation: budget.truncation,
    }
}

fn scan_call_sites(
    query: &Query,
    parsed: &ParsedSource,
    function: &str,
    cursor: &mut QueryCursor,
    progress: &mut QueryProgress,
) -> (Vec<Value>, CursorBudget) {
    let mut callback = |_: &QueryCursorState| progress.observe();
    let options = QueryCursorOptions::new().progress_callback(&mut callback);
    let mut stream = cursor.matches_with_options(
        query,
        parsed.tree.root_node(),
        parsed.bytes.as_slice(),
        options,
    );
    let mut hits = Vec::new();
    let mut budget = CursorBudget::default();
    while let Some(query_match) = stream.next() {
        let Some(hit) = prepare_call_site(
            query,
            parsed,
            function,
            query_match.captures,
            &mut budget,
            hits.len(),
        ) else {
            break;
        };
        if let Some(hit) = hit {
            hits.push(hit);
        }
    }
    (hits, budget)
}

fn prepare_call_site(
    query: &Query,
    parsed: &ParsedSource,
    function: &str,
    captures: &[tree_sitter::QueryCapture<'_>],
    budget: &mut CursorBudget,
    result_count: usize,
) -> Option<Option<Value>> {
    if !budget.begin_match() {
        return None;
    }
    let Some(hit) = call_site_for_match(query, parsed, function, captures, budget) else {
        return Some(None);
    };
    if !budget.accept_result(result_count, MAX_CALLER_RESULT_LIMIT) {
        return None;
    }
    Some(Some(hit))
}

#[derive(Default)]
struct QueryProgress {
    calls: usize,
    exhausted: bool,
}

impl QueryProgress {
    fn observe(&mut self) -> ControlFlow<()> {
        self.calls = self.calls.saturating_add(1);
        self.exhausted = self.calls >= MAX_CURSOR_PROGRESS_CALLBACKS;
        if self.exhausted {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

fn bounded_query_cursor() -> QueryCursor {
    let mut cursor = QueryCursor::new();
    cursor.set_match_limit(MAX_IN_PROGRESS_MATCHES);
    cursor
}

fn call_site_for_match(
    query: &Query,
    parsed: &ParsedSource,
    function: &str,
    captures: &[tree_sitter::QueryCapture<'_>],
    budget: &mut CursorBudget,
) -> Option<Value> {
    let allowance = budget.capture_allowance(captures.len());
    captures
        .iter()
        .take(allowance)
        .find_map(|capture| call_site_capture(query, parsed, function, captures, capture))
}

fn call_site_capture(
    query: &Query,
    parsed: &ParsedSource,
    function: &str,
    captures: &[tree_sitter::QueryCapture<'_>],
    capture: &tree_sitter::QueryCapture<'_>,
) -> Option<Value> {
    let index = usize::try_from(capture.index).ok()?;
    if query.capture_names().get(index).copied()? != "callee" {
        return None;
    }
    let captured_text = bounded_node_text(&capture.node, &parsed.bytes, MAX_FUNCTION_BYTES)?;
    if !callee_matches(&captured_text, function) {
        return None;
    }
    let call_node = capture
        .node
        .parent()
        .or_else(|| captures.first().map(|c| c.node))
        .unwrap_or(capture.node);
    Some(json!({
        "callee": captured_text,
        "call": node_summary(&call_node, &parsed.bytes),
    }))
}

fn finish_cursor_budget(budget: &mut CursorBudget, cursor: &QueryCursor, progress_exhausted: bool) {
    if cursor.did_exceed_match_limit() {
        budget.truncation.mark("in_progress_match_limit");
    }
    if progress_exhausted {
        budget.truncation.mark("cursor_work_limit");
    }
}

struct NodeAtRequest {
    file: PathBuf,
    language: String,
    line: usize,
    column: Option<usize>,
}

impl NodeAtRequest {
    fn from_json(args: &Value) -> Result<Self> {
        validate_argument_object(args, &["file", "language", "line", "column"])?;
        Ok(Self {
            file: PathBuf::from(read_bounded_string(args, "file", MAX_FILE_PATH_BYTES)?),
            language: read_bounded_string(args, "language", MAX_LANGUAGE_BYTES)?,
            line: read_bounded_usize(args, "line", MAX_POSITION_INPUT)?,
            column: read_optional_bounded_usize(args, "column", MAX_POSITION_INPUT)?,
        })
    }
}

#[derive(Debug)]
struct QueryRequest {
    file: PathBuf,
    language: String,
    query: String,
    limit: usize,
}

impl QueryRequest {
    fn from_json(args: &Value) -> Result<Self> {
        validate_argument_object(args, &["file", "language", "query", "limit"])?;
        Ok(Self {
            file: PathBuf::from(read_bounded_string(args, "file", MAX_FILE_PATH_BYTES)?),
            language: read_bounded_string(args, "language", MAX_LANGUAGE_BYTES)?,
            query: read_bounded_string(args, "query", MAX_QUERY_BYTES)?,
            limit: read_optional_bounded_usize(args, "limit", MAX_QUERY_RESULT_LIMIT)?
                .unwrap_or(DEFAULT_QUERY_RESULT_LIMIT),
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
        validate_argument_object(args, &["file", "language", "function"])?;
        Ok(Self {
            file: PathBuf::from(read_bounded_string(args, "file", MAX_FILE_PATH_BYTES)?),
            language: read_bounded_string(args, "language", MAX_LANGUAGE_BYTES)?,
            function: read_bounded_string(args, "function", MAX_FUNCTION_BYTES)?,
        })
    }
}

fn validate_argument_object(args: &Value, allowed: &[&str]) -> Result<()> {
    let object = args
        .as_object()
        .context("tool arguments must be a JSON object")?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        anyhow::bail!("unknown tool argument `{field}`");
    }
    Ok(())
}

fn read_bounded_string(args: &Value, field: &str, max_bytes: usize) -> Result<String> {
    let text = args
        .get(field)
        .with_context(|| format!("missing required field `{field}`"))?
        .as_str()
        .with_context(|| format!("field `{field}` must be a string"))?;
    if text.is_empty() {
        anyhow::bail!("field `{field}` must not be empty");
    }
    if text.len() > max_bytes {
        anyhow::bail!("field `{field}` exceeds the {max_bytes}-byte limit");
    }
    Ok(text.to_string())
}

fn read_optional_bounded_usize(args: &Value, field: &str, maximum: usize) -> Result<Option<usize>> {
    args.get(field)
        .map(|value| parse_bounded_usize(value, field, maximum))
        .transpose()
}

fn read_bounded_usize(args: &Value, field: &str, maximum: usize) -> Result<usize> {
    let value = args
        .get(field)
        .with_context(|| format!("missing required field `{field}`"))?;
    parse_bounded_usize(value, field, maximum)
}

fn parse_bounded_usize(value: &Value, field: &str, maximum: usize) -> Result<usize> {
    let raw = value
        .as_u64()
        .with_context(|| format!("field `{field}` must be a positive integer"))?;
    let converted = usize::try_from(raw)
        .with_context(|| format!("field `{field}` is outside the supported integer range"))?;
    if converted == 0 || converted > maximum {
        anyhow::bail!("field `{field}` must be between 1 and {maximum}");
    }
    Ok(converted)
}

fn validate_query_budget(query: &Query) -> Result<()> {
    if query.pattern_count() > MAX_QUERY_PATTERNS {
        anyhow::bail!("tree-sitter query exceeds the {MAX_QUERY_PATTERNS}-pattern limit");
    }
    if query.capture_names().len() > MAX_QUERY_CAPTURE_NAMES {
        anyhow::bail!("tree-sitter query exceeds the {MAX_QUERY_CAPTURE_NAMES}-capture-name limit");
    }
    Ok(())
}

fn validate_query_text_budget(query: &str) -> Result<()> {
    let capture_references = query.bytes().filter(|byte| *byte == b'@').count();
    if capture_references > MAX_QUERY_CAPTURE_REFERENCES {
        anyhow::bail!(
            "tree-sitter query exceeds the {MAX_QUERY_CAPTURE_REFERENCES}-capture-reference limit"
        );
    }
    Ok(())
}

fn grammar_for(language: &str) -> Result<Language> {
    Ok(match language {
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        other => anyhow::bail!(
            "unsupported language `{other}`; supported: {}",
            supported_language_list()
        ),
    })
}

fn callers_pattern(language: &str) -> Result<&'static str> {
    // Capture the callee identifier of every call expression. The grammar
    // names differ a bit per language; the table covers each one exactly.
    // There is no permissive fallback — an unsupported language is a hard
    // error so a misparse can't silently masquerade as "no callers".
    callers_pattern_table()
        .iter()
        .find_map(|(languages, pattern)| languages.contains(&language).then_some(*pattern))
        .with_context(|| {
            format!(
                "no callers query pattern for language `{language}`; supported: {}",
                supported_language_list()
            )
        })
}

fn callers_pattern_table() -> &'static [(&'static [&'static str], &'static str)] {
    &[
        (
            &["javascript", "typescript"],
            "(call_expression function: (_) @callee)",
        ),
        (&["python"], "(call function: (_) @callee)"),
        (&["c"], "(call_expression function: (_) @callee)"),
        (
            &["cpp"],
            "(call_expression function: (_) @callee) (new_expression type: (_) @callee)",
        ),
        (&["java"], "(method_invocation name: (identifier) @callee)"),
        (&["ruby"], "(call method: (identifier) @callee)"),
        (&["php"], "(function_call_expression function: (_) @callee)"),
        (&["go"], "(call_expression function: (_) @callee)"),
        (
            &["rust"],
            "(call_expression function: (_) @callee) (macro_invocation macro: (_) @callee)",
        ),
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

fn bounded_node_text(node: &Node<'_>, source: &[u8], max_bytes: usize) -> Option<String> {
    let length = node.end_byte().checked_sub(node.start_byte())?;
    if length > max_bytes {
        return None;
    }
    node.utf8_text(source).ok().map(str::to_string)
}

fn node_summary(node: &Node<'_>, source: &[u8]) -> Value {
    let start = node.start_position();
    let end = node.end_position();
    let first_line = node
        .utf8_text(source)
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .trim();
    let snippet = truncate_utf8_bytes(first_line, MAX_SNIPPET_BYTES);
    json!({
        "kind": node.kind(),
        "byte_range": [node.start_byte(), node.end_byte()],
        "start": {"row": start.row.saturating_add(1), "column": start.column.saturating_add(1)},
        "end": {"row": end.row.saturating_add(1), "column": end.column.saturating_add(1)},
        "snippet": snippet,
    })
}

fn truncate_utf8_bytes(text: &str, max_bytes: usize) -> String {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text[..end].to_string()
}

fn bounded_tool_response(
    mut response: Value,
    array_field: &str,
    count_field: Option<&str>,
) -> Result<Value> {
    while response_exceeds_budget(&response)? {
        if !truncate_response_array(&mut response, array_field) {
            anyhow::bail!(
                "tree-sitter response metadata exceeds the {MAX_TOOL_RESPONSE_BYTES}-byte limit"
            );
        }
        mark_response_truncated(&mut response, "response_byte_limit")?;
        sync_response_count(&mut response, array_field, count_field)?;
    }
    Ok(response)
}

fn response_exceeds_budget(response: &Value) -> Result<bool> {
    let mut writer = ResponseBudgetWriter::default();
    match serde_json::to_writer(&mut writer, response) {
        Ok(()) => Ok(false),
        Err(_) if writer.exceeded => Ok(true),
        Err(error) => Err(error).context("could not serialize tree-sitter response"),
    }
}

#[derive(Default)]
struct ResponseBudgetWriter {
    written: usize,
    exceeded: bool,
}

impl io::Write for ResponseBudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self.written.checked_add(bytes.len());
        if next.is_none_or(|length| length > MAX_TOOL_RESPONSE_BYTES) {
            self.exceeded = true;
            return Err(io::Error::other("tree-sitter response budget exceeded"));
        }
        self.written = next.unwrap_or(MAX_TOOL_RESPONSE_BYTES);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn truncate_response_array(response: &mut Value, field: &str) -> bool {
    let Some(values) = response.get_mut(field).and_then(Value::as_array_mut) else {
        return false;
    };
    if values.is_empty() {
        return false;
    }
    values.truncate(values.len() / 2);
    true
}

fn mark_response_truncated(response: &mut Value, reason: &'static str) -> Result<()> {
    let object = response
        .as_object_mut()
        .context("tree-sitter response must be an object")?;
    object.insert("truncated".to_string(), Value::Bool(true));
    let reasons = object
        .entry("truncation_reasons")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("tree-sitter truncation reasons must be an array")?;
    if !reasons.iter().any(|candidate| candidate == reason) {
        reasons.push(Value::String(reason.to_string()));
    }
    Ok(())
}

fn sync_response_count(
    response: &mut Value,
    array_field: &str,
    count_field: Option<&str>,
) -> Result<()> {
    let Some(count_field) = count_field else {
        return Ok(());
    };
    let count = response
        .get(array_field)
        .and_then(Value::as_array)
        .map(Vec::len)
        .context("tree-sitter response result array is missing")?;
    response[count_field] = json!(count);
    sync_query_capture_count(response, array_field)?;
    Ok(())
}

fn sync_query_capture_count(response: &mut Value, array_field: &str) -> Result<()> {
    if array_field != "matches" || response.get("capture_count").is_none() {
        return Ok(());
    }
    let captures = response["matches"]
        .as_array()
        .context("tree-sitter matches must be an array")?
        .iter()
        .filter_map(|matched| matched["captures"].as_array())
        .map(Vec::len)
        .sum::<usize>();
    response["capture_count"] = json!(captures);
    Ok(())
}

fn nth_line_start(bytes: &[u8], line_index: usize) -> Option<usize> {
    if line_index == 0 {
        return Some(0);
    }
    bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(line_index.saturating_sub(1))
        .and_then(|(offset, _)| offset.checked_add(1))
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
        column = column.saturating_add(1);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_mcp_treesitter::SUPPORTED_LANGUAGES;
    use tempfile::NamedTempFile;

    fn write_temp(content: &str, suffix: &str) -> NamedTempFile {
        let file = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
        std::fs::write(file.path(), content).unwrap();
        file
    }

    fn context_for(file: &NamedTempFile) -> TreeSitterContext {
        TreeSitterContext::new(
            ReadRootCapability::new([file.path().parent().unwrap().to_path_buf()]).unwrap(),
        )
    }

    fn registry_for(file: &NamedTempFile) -> ToolRegistry {
        build_registry_with_capability(
            ReadRootCapability::new([file.path().parent().unwrap().to_path_buf()]).unwrap(),
        )
    }

    fn capture_query(captures: usize) -> String {
        assert!(captures > 0);
        (1..captures).fold("(identifier) @capture_0".to_string(), |query, index| {
            format!("(parenthesized_expression {query}) @capture_{index}")
        })
    }

    fn has_truncation_reason(response: &Value, reason: &str) -> bool {
        response["truncation_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.iter().any(|value| value.as_str() == Some(reason)))
    }

    #[tokio::test]
    async fn node_at_locates_a_call_expression() {
        let src = "function main() {\n    db.query(req.query.id);\n}\n";
        let file = write_temp(src, ".js");
        let resp = NodeAtHandler(context_for(&file))
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
        let resp = QueryHandler(context_for(&file))
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
        let resp = CallersHandler(context_for(&file))
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
        let file = write_temp("IDENTIFICATION DIVISION.", ".cbl");
        let err = NodeAtHandler(context_for(&file))
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "cobol",
                "line": 1
            }))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unsupported language"));
    }

    #[tokio::test]
    async fn handler_rejects_a_file_outside_its_read_root() {
        let root = tempfile::tempdir().unwrap();
        let file = write_temp("int main(void) {}\n", ".c");
        let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();

        let error = NodeAtHandler(TreeSitterContext::new(capability))
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "c",
                "line": 1
            }))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("outside the MCP read roots"));
    }

    #[tokio::test]
    async fn handler_resolves_relative_paths_against_the_declared_root() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("src/main.c");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, "int main(void) {}\n").unwrap();
        let capability = ReadRootCapability::new([root.path().to_path_buf()]).unwrap();

        let response = NodeAtHandler(TreeSitterContext::new(capability))
            .call(json!({"file": "src/main.c", "language": "c", "line": 1}))
            .await
            .unwrap();

        assert_eq!(
            response["file"],
            std::fs::canonicalize(source).unwrap().display().to_string()
        );
    }

    #[test]
    fn parsed_source_cache_hits_then_invalidates_after_a_file_change() {
        let file = write_temp("int main(void) {}\n", ".c");
        let context = context_for(&file);

        let first = parse_source_file(&context, file.path(), "c").unwrap();
        let cached = parse_source_file(&context, file.path(), "c").unwrap();
        assert!(Arc::ptr_eq(&first, &cached));

        std::fs::write(file.path(), "int changed(void) { return 1; }\n").unwrap();
        let changed = parse_source_file(&context, file.path(), "c").unwrap();

        assert!(!Arc::ptr_eq(&first, &changed));
        assert_ne!(first.bytes, changed.bytes);
    }

    #[test]
    fn parsed_source_cache_invalidates_equal_length_rewrite_with_restored_mtime() {
        let file = write_temp("int main(void) {}\n", ".c");
        let context = context_for(&file);
        let original_mtime = std::fs::metadata(file.path()).unwrap().modified().unwrap();
        let first = parse_source_file(&context, file.path(), "c").unwrap();

        std::fs::write(file.path(), "int evil(void) {}\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(file.path())
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();
        assert_eq!(
            std::fs::metadata(file.path()).unwrap().modified().unwrap(),
            original_mtime
        );
        let changed = parse_source_file(&context, file.path(), "c").unwrap();

        assert!(!Arc::ptr_eq(&first, &changed));
        assert_eq!(changed.bytes, b"int evil(void) {}\n");
    }

    #[test]
    fn query_limit_is_rejected_and_oversized_sources_fail_closed() {
        let error = QueryRequest::from_json(&json!({
            "file": "source.c",
            "language": "c",
            "query": "(_) @node",
            "limit": u64::MAX,
        }))
        .unwrap_err();
        assert!(error.to_string().contains("between 1 and 500"));

        let file = write_temp("", ".c");
        std::fs::File::options()
            .write(true)
            .open(file.path())
            .unwrap()
            .set_len(MAX_SOURCE_FILE_BYTES as u64 + 1)
            .unwrap();
        let error = match parse_source_file(&context_for(&file), file.path(), "c") {
            Ok(_) => panic!("oversized source unexpectedly parsed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("maximum supported size"));
    }

    #[tokio::test]
    async fn callers_caps_excessive_results_and_reports_truncation() {
        let calls = (0..MAX_CALLER_RESULT_LIMIT + 25)
            .map(|_| "target();")
            .collect::<Vec<_>>()
            .join("\n");
        let file = write_temp(&format!("void run(void) {{\n{calls}\n}}\n"), ".c");

        let response = CallersHandler(context_for(&file))
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "c",
                "function": "target",
            }))
            .await
            .unwrap();

        assert_eq!(
            response["hits"].as_array().unwrap().len(),
            MAX_CALLER_RESULT_LIMIT
        );
        assert_eq!(response["truncated"], json!(true));
        assert!(has_truncation_reason(&response, "result_limit"));
    }

    #[tokio::test]
    async fn direct_registry_dispatch_rejects_extreme_and_malformed_arguments() {
        let file = write_temp("int main(void) {}\n", ".c");
        let path = file.path().display().to_string();
        let registry = registry_for(&file);
        let cases = [
            (
                "tree_sitter:node_at",
                json!({"file": path, "language": "c", "line": u64::MAX}),
            ),
            (
                "tree_sitter:node_at",
                json!({"file": path, "language": "c", "line": 1, "column": u64::MAX}),
            ),
            (
                "tree_sitter:node_at",
                json!({"file": path, "language": "c", "line": 1, "surprise": true}),
            ),
            (
                "tree_sitter:query",
                json!({"file": path, "language": "c", "query": "(_) @node", "limit": "many"}),
            ),
            ("tree_sitter:callers", json!([])),
        ];

        for (tool, arguments) in cases {
            let error = registry.call(tool, arguments).await.unwrap_err();
            assert!(
                error.to_string().contains("advertised input schema"),
                "schema-invalid arguments for {tool} reached the handler: {error}"
            );
        }
    }

    #[tokio::test]
    async fn direct_registry_rejects_oversized_queries_and_columns_past_the_line() {
        let file = write_temp("int main(void) {}\n", ".c");
        let path = file.path().display().to_string();
        let registry = registry_for(&file);
        let oversized = "x".repeat(MAX_QUERY_BYTES + 1);

        let query_error = registry
            .call(
                "tree_sitter:query",
                json!({"file": path, "language": "c", "query": oversized}),
            )
            .await
            .unwrap_err();
        let column_error = registry
            .call(
                "tree_sitter:node_at",
                json!({"file": path, "language": "c", "line": 1, "column": 1000}),
            )
            .await
            .unwrap_err();
        let capture_error = registry
            .call(
                "tree_sitter:query",
                json!({
                    "file": path,
                    "language": "c",
                    "query": capture_query(MAX_QUERY_CAPTURE_REFERENCES + 1),
                }),
            )
            .await
            .unwrap_err();

        assert!(query_error.to_string().contains("advertised input schema"));
        assert!(column_error.to_string().contains("past end of line"));
        assert!(capture_error
            .to_string()
            .contains("capture-reference limit"));
    }

    #[tokio::test]
    async fn query_rejects_excessive_pattern_count() {
        let file = write_temp("int main(void) { int value = 1; }\n", ".c");
        let patterns = (0..MAX_QUERY_PATTERNS + 1)
            .map(|_| "(identifier)")
            .collect::<Vec<_>>()
            .join("\n");

        let error = QueryHandler(context_for(&file))
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "c",
                "query": patterns,
            }))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("128-pattern limit"));
    }

    #[tokio::test]
    async fn query_caps_capture_explosions_and_serialized_output() {
        let identifier = "identifier_".to_string() + &"x".repeat(300);
        let nesting = MAX_CAPTURES_PER_MATCH - 1;
        let expressions = (0..40)
            .map(|index| {
                format!(
                    "{}{}_{}{};",
                    "(".repeat(nesting),
                    identifier,
                    index,
                    ")".repeat(nesting)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let file = write_temp(&expressions, ".js");

        let response = QueryHandler(context_for(&file))
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "javascript",
                "query": capture_query(MAX_CAPTURES_PER_MATCH),
                "limit": MAX_QUERY_RESULT_LIMIT,
            }))
            .await
            .unwrap();

        assert!(serde_json::to_vec(&response).unwrap().len() <= MAX_TOOL_RESPONSE_BYTES);
        assert!(response["capture_count"].as_u64().unwrap() <= MAX_AGGREGATE_CAPTURES as u64);
        assert!(has_truncation_reason(&response, "aggregate_capture_limit"));
        assert!(has_truncation_reason(&response, "response_byte_limit"));
        let matches = response["matches"].as_array().unwrap();
        assert!(matches.iter().all(|matched| {
            matched["captures"].as_array().unwrap().len() <= MAX_CAPTURES_PER_MATCH
        }));
    }

    #[test]
    fn cursor_budget_caps_captures_per_match_and_in_aggregate() {
        let mut budget = CursorBudget::default();

        assert_eq!(
            budget.capture_allowance(MAX_CAPTURES_PER_MATCH + 1),
            MAX_CAPTURES_PER_MATCH
        );
        assert!(budget
            .truncation
            .reasons
            .contains(&"captures_per_match_limit"));
        budget.capture_count = MAX_AGGREGATE_CAPTURES;
        assert_eq!(budget.capture_allowance(1), 0);
        assert!(budget
            .truncation
            .reasons
            .contains(&"aggregate_capture_limit"));
    }

    #[tokio::test]
    async fn query_result_limit_is_explicit_and_preserves_source_order() {
        let file = write_temp("let first = 1;\nlet second = 2;\nlet third = 3;\n", ".js");

        let response = QueryHandler(context_for(&file))
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "javascript",
                "query": "(identifier) @name",
                "limit": 2,
            }))
            .await
            .unwrap();

        assert_eq!(response["match_count"], json!(2));
        assert!(has_truncation_reason(&response, "result_limit"));
        let matches = response["matches"].as_array().unwrap();
        let first_byte = matches[0]["captures"][0]["node"]["byte_range"][0]
            .as_u64()
            .unwrap();
        let second_byte = matches[1]["captures"][0]["node"]["byte_range"][0]
            .as_u64()
            .unwrap();
        assert!(first_byte < second_byte);
    }

    #[tokio::test]
    async fn node_at_caps_deep_parent_chains_and_long_snippets() {
        let prefix = "let value = ";
        let opening = "(".repeat(MAX_PARENT_CHAIN_NODES + 24);
        let source = format!(
            "{prefix}{opening}{}{};\n",
            "x".repeat(512),
            ")".repeat(MAX_PARENT_CHAIN_NODES + 24)
        );
        let file = write_temp(&source, ".js");
        let column = prefix.len() + opening.len() + 1;

        let response = NodeAtHandler(context_for(&file))
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "javascript",
                "line": 1,
                "column": column,
            }))
            .await
            .unwrap();

        assert!(serde_json::to_vec(&response).unwrap().len() <= MAX_TOOL_RESPONSE_BYTES);
        assert!(has_truncation_reason(&response, "parent_chain_limit"));
        let summaries = std::iter::once(&response["node"])
            .chain(response["parents"].as_array().unwrap().iter());
        assert!(summaries
            .map(|node| node["snippet"].as_str().unwrap().len())
            .all(|len| len <= MAX_SNIPPET_BYTES));
    }

    #[tokio::test]
    async fn callers_stops_after_the_cursor_match_budget() {
        let calls = (0..MAX_CURSOR_MATCHES + 1)
            .map(|_| "other();")
            .collect::<Vec<_>>()
            .join("\n");
        let file = write_temp(&format!("void run(void) {{\n{calls}\n}}\n"), ".c");

        let response = CallersHandler(context_for(&file))
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "c",
                "function": "target",
            }))
            .await
            .unwrap();

        assert_eq!(response["examined_match_count"], json!(MAX_CURSOR_MATCHES));
        assert!(has_truncation_reason(&response, "cursor_match_limit"));
    }

    #[test]
    fn node_position_arithmetic_never_wraps_or_panics() {
        let source = b"a\nxyz\n";
        let positions = [
            (0, None),
            (1, Some(0)),
            (1, Some(1)),
            (1, Some(usize::MAX)),
            (usize::MAX, Some(usize::MAX)),
        ];

        for (line, column) in positions {
            let outcome = std::panic::catch_unwind(|| node_target_byte(source, line, column));
            assert!(outcome.is_ok(), "position arithmetic panicked");
        }
        assert_eq!(node_target_byte(source, 2, Some(4)).unwrap().byte, 5);
        assert!(node_target_byte(source, 2, Some(5)).is_err());
    }

    #[test]
    fn non_first_line_offsets_are_applied_exactly_once() {
        let first_line = "x".repeat(16 * 1024);
        let source = format!("{first_line}\n    target();\n");
        let line_start = first_line.len() + 1;

        let target = node_target_byte(source.as_bytes(), 2, None).unwrap();

        assert_eq!(target.column, 4);
        assert_eq!(target.byte, line_start + 4);
    }

    fn parent_chain_kinds(response: &Value) -> Vec<String> {
        std::iter::once(&response["node"])
            .chain(response["parents"].as_array().unwrap().iter())
            .filter_map(|node| node["kind"].as_str().map(str::to_string))
            .collect()
    }

    async fn callers_count(file: &NamedTempFile, language: &str, function: &str) -> usize {
        let response = CallersHandler(context_for(file))
            .call(json!({
                "file": file.path().display().to_string(),
                "language": language,
                "function": function,
            }))
            .await
            .unwrap();
        response["hits"].as_array().unwrap().len()
    }

    #[tokio::test]
    async fn cpp_parses_with_the_cpp_grammar_not_the_c_grammar() {
        let src = "namespace ns {\ntemplate <typename T>\nclass Repo {\n  void run() {\n    db_->query(id);\n  }\n  T* db_;\n};\n}\n";
        let file = write_temp(src, ".cc");
        let response = NodeAtHandler(context_for(&file))
            .call(json!({
                "file": file.path().display().to_string(),
                "language": "cpp",
                "line": 5,
            }))
            .await
            .unwrap();

        assert_eq!(response["found"], json!(true));
        let kinds = parent_chain_kinds(&response);
        assert!(
            kinds.iter().any(|kind| kind == "template_declaration"),
            "{kinds:?}"
        );
        assert!(
            kinds.iter().any(|kind| kind == "class_specifier"),
            "{kinds:?}"
        );
        assert!(!kinds.iter().any(|kind| kind == "ERROR"), "{kinds:?}");
    }

    #[tokio::test]
    async fn known_caller_set_per_language() {
        let cpp = "void f(){ q(1); o.q(2); p->q(3); Ns::q(4); new Q(5); }\n";
        let fixtures = [
            ("c", ".c", "void f(void){ q(); q(); other(); }\n", "q", 2),
            ("cpp", ".cc", cpp, "q", 4),
            ("cpp", ".cc", cpp, "Q", 1),
            (
                "go",
                ".go",
                "package main\nfunc f() { q(); o.q(); other() }\n",
                "q",
                2,
            ),
            (
                "java",
                ".java",
                "class C { void f(){ q(); o.q(); other(); } }\n",
                "q",
                2,
            ),
            (
                "javascript",
                ".js",
                "function f(){ q(); o.q(); other(); }\n",
                "q",
                2,
            ),
            ("php", ".php", "<?php q(); q(); other(); ?>\n", "q", 2),
            ("python", ".py", "q()\no.q()\nother()\n", "q", 2),
            ("ruby", ".rb", "q(1)\no.q(2)\nother(3)\n", "q", 2),
            (
                "rust",
                ".rs",
                "fn m(){ foo(); x.foo(); Ty::foo(); foofoo(); }\n",
                "foo",
                3,
            ),
            (
                "typescript",
                ".ts",
                "function f(){ q(); o.q(); other(); }\n",
                "q",
                2,
            ),
        ];
        for (language, suffix, source, function, expected) in fixtures {
            let file = write_temp(source, suffix);
            let hits = callers_count(&file, language, function).await;
            assert_eq!(hits, expected, "{language} callers({function})");
        }
    }

    #[tokio::test]
    async fn rust_macro_call_sites_are_found() {
        let src = "fn m(){ let s = format!(\"{}\", x); write!(f, \"{}\", y).unwrap(); }\n";
        let file = write_temp(src, ".rs");
        assert_eq!(callers_count(&file, "rust", "format").await, 1);
        assert_eq!(callers_count(&file, "rust", "write").await, 1);
    }

    #[test]
    fn every_supported_language_has_a_compiling_grammar_and_caller_pattern() {
        for &language in SUPPORTED_LANGUAGES {
            let grammar = grammar_for(language).expect("grammar compiles in");
            let pattern = callers_pattern(language).expect("callers pattern exists");
            Query::new(&grammar, pattern).expect("callers query compiles");
        }
    }

    #[test]
    fn callers_pattern_has_no_permissive_fallback() {
        let message = callers_pattern("cobol").unwrap_err().to_string();
        assert!(message.contains("cpp"), "{message}");
        assert!(message.contains("rust"), "{message}");
    }

    #[test]
    fn schema_language_descriptions_match_the_supported_set() {
        let expected = language_schema_description();
        for descriptor in [
            node_at_descriptor(),
            query_descriptor(),
            callers_descriptor(),
        ] {
            let description = descriptor.input_schema["properties"]["language"]["description"]
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(description, expected);
            for &language in SUPPORTED_LANGUAGES {
                assert!(
                    description.contains(language),
                    "{language} in {description}"
                );
            }
        }
    }

    #[test]
    fn unsupported_language_error_names_the_supported_set() {
        let message = grammar_for("cobol").unwrap_err().to_string();
        assert!(message.contains(&supported_language_list()), "{message}");
    }
}
