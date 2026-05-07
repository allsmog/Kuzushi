//! clang MCP tool implementations.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use kuzushi_mcp_common::doctor::{probe_all, which, HealthSummary};
use kuzushi_mcp_common::schema::{Position, Range};
use kuzushi_mcp_common::tool::{Tool, ToolHandler, ToolRegistry};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::clangd::{parse_locations, ClangdClient};
use crate::compile_db;

const PROBES: &[(&str, &[&str])] = &[("clangd", &["--version"]), ("clang", &["--version"])];

pub async fn health_summary() -> HealthSummary {
    probe_all(PROBES).await
}

/// One process-wide cached clangd connection per repo. Hand-built because
/// we don't want to require a shared async-runtime context across tool
/// callers; tools acquire+lock the connection per call.
#[derive(Default)]
struct ClangdHandle(Mutex<Option<(PathBuf, Arc<ClangdClient>)>>);

impl ClangdHandle {
    async fn for_repo(&self, repo: &std::path::Path) -> Result<Arc<ClangdClient>> {
        let canonical = std::fs::canonicalize(repo)?;
        let mut guard = self.0.lock().await;
        if let Some(client) = cached_clangd_client(&mut guard, &canonical).await {
            return Ok(client);
        }
        let client = start_clangd_client(&canonical).await?;
        *guard = Some((canonical, client.clone()));
        Ok(client)
    }
}

async fn cached_clangd_client(
    guard: &mut Option<(PathBuf, Arc<ClangdClient>)>,
    canonical: &std::path::Path,
) -> Option<Arc<ClangdClient>> {
    let Some((existing, client)) = guard.as_ref() else {
        return None;
    };
    if existing == canonical {
        return Some(client.clone());
    }
    // Different repo: best-effort shutdown of the prior client.
    let _ = client.shutdown().await;
    None
}

async fn start_clangd_client(canonical: &std::path::Path) -> Result<Arc<ClangdClient>> {
    let client = Arc::new(ClangdClient::spawn(canonical).await?);
    client.initialize(canonical).await?;
    Ok(client)
}

pub fn build_registry() -> ToolRegistry {
    let handle = Arc::new(ClangdHandle::default());

    ToolRegistry::new()
        .register(
            Tool {
                name: "clang.health".into(),
                description: "Report whether clangd and clang are available, with versions.".into(),
                input_schema: json!({"type": "object", "properties": {}}),
            },
            HealthTool,
        )
        .register(
            Tool {
                name: "clang.compile_commands".into(),
                description: "Locate or generate compile_commands.json for a repo.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath"],
                    "properties": { "repoPath": {"type": "string"} }
                }),
            },
            CompileCommandsTool,
        )
        .register(
            Tool {
                name: "clang.definition".into(),
                description: "Forward to clangd `textDocument/definition` and return canonical Locations.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            DefinitionTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.references".into(),
                description: "Forward to clangd `textDocument/references` and return canonical Locations.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            ReferencesTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.type_at".into(),
                description: "Forward to clangd `textDocument/hover` and return type information at a position.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            TypeAtTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.ast".into(),
                description: "Forward to clangd `textDocument/ast` (clangd extension) and return the AST subtree at a position.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            AstTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.callers".into(),
                description: "Incoming call-hierarchy: methods that call the symbol at (file, line, column). Wraps clangd `callHierarchy/incomingCalls`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            CallersTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.callees".into(),
                description: "Outgoing call-hierarchy: methods called by the symbol at (file, line, column). Wraps clangd `callHierarchy/outgoingCalls`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            CalleesTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.macro_expand".into(),
                description: "Macro expansion at a position via clangd hover (clangd renders the expansion in markdown).".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file", "line", "column"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"},
                        "line": {"type": "integer", "minimum": 1},
                        "column": {"type": "integer", "minimum": 1}
                    }
                }),
            },
            MacroExpandTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.semantic_tokens".into(),
                description: "Semantic tokens for an entire file via `textDocument/semanticTokens/full`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"}
                    }
                }),
            },
            SemanticTokensTool {
                handle: handle.clone(),
            },
        )
        .register(
            Tool {
                name: "clang.diagnostics".into(),
                description: "Pull-mode diagnostics for a file via LSP 3.17 `textDocument/diagnostic`.".into(),
                input_schema: json!({
                    "type": "object",
                    "required": ["repoPath", "file"],
                    "properties": {
                        "repoPath": {"type": "string"},
                        "file": {"type": "string"}
                    }
                }),
            },
            DiagnosticsTool {
                handle: handle.clone(),
            },
        )
}

#[allow(dead_code)]
fn stub_descriptor(name: &'static str, desc: &'static str) -> Tool {
    Tool {
        name: name.into(),
        description: desc.into(),
        input_schema: json!({"type": "object"}),
    }
}

struct HealthTool;
struct CompileCommandsTool;
struct DefinitionTool {
    handle: Arc<ClangdHandle>,
}
struct ReferencesTool {
    handle: Arc<ClangdHandle>,
}
struct TypeAtTool {
    handle: Arc<ClangdHandle>,
}
struct AstTool {
    handle: Arc<ClangdHandle>,
}
struct CallersTool {
    handle: Arc<ClangdHandle>,
}
struct CalleesTool {
    handle: Arc<ClangdHandle>,
}
struct MacroExpandTool {
    handle: Arc<ClangdHandle>,
}
struct SemanticTokensTool {
    handle: Arc<ClangdHandle>,
}
struct DiagnosticsTool {
    handle: Arc<ClangdHandle>,
}
/// Kept for any future stub we register before wiring; unused now that
/// all 11 planned tools are live.
#[allow(dead_code)]
struct NotYetImplemented(&'static str);

#[async_trait]
impl ToolHandler for HealthTool {
    async fn call(&self, _args: Value) -> Result<Value> {
        Ok(serde_json::to_value(health_summary().await)?)
    }
}

fn ensure_clangd() -> Result<()> {
    if which("clangd").is_none() {
        anyhow::bail!(
            "BackendUnavailable: clangd not on PATH. Install LLVM (e.g. `apt install clangd` / `brew install llvm`)."
        );
    }
    Ok(())
}

fn require_str<'a>(args: &'a Value, name: &str) -> Result<&'a str> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {name}"))
}

fn require_u32(args: &Value, name: &str) -> Result<u32> {
    args.get(name)
        .and_then(Value::as_u64)
        .map(|n| n as u32)
        .ok_or_else(|| anyhow::anyhow!("missing required integer argument: {name}"))
}

struct FileRequest {
    repo: PathBuf,
    file: PathBuf,
}

impl FileRequest {
    fn from_args(args: &Value) -> Result<Self> {
        let repo = PathBuf::from(require_str(args, "repoPath")?);
        let file = repo.join(require_str(args, "file")?);
        Ok(Self { repo, file })
    }

    async fn client(&self, handle: &ClangdHandle) -> Result<Arc<ClangdClient>> {
        handle.for_repo(&self.repo).await
    }

    fn text_document(&self) -> Value {
        json!({ "textDocument": { "uri": format!("file://{}", self.file.display()) } })
    }
}

struct PositionRequest {
    file: FileRequest,
    line: u32,
    column: u32,
}

impl PositionRequest {
    fn from_args(args: &Value) -> Result<Self> {
        let file = FileRequest::from_args(args)?;
        let line = require_u32(args, "line")?;
        let column = require_u32(args, "column")?;
        Ok(Self { file, line, column })
    }

    fn from_args_with_default_column(args: &Value, default_column: u32) -> Result<Self> {
        let file = FileRequest::from_args(args)?;
        let line = require_u32(args, "line")?;
        let column = optional_u32(args, "column").unwrap_or(default_column);
        Ok(Self { file, line, column })
    }

    async fn client(&self, handle: &ClangdHandle) -> Result<Arc<ClangdClient>> {
        self.file.client(handle).await
    }

    fn params(&self) -> Value {
        position_arg(&self.file.file, self.line, self.column)
    }
}

fn optional_u32(args: &Value, name: &str) -> Option<u32> {
    args.get(name).and_then(Value::as_u64).map(|n| n as u32)
}

#[async_trait]
impl ToolHandler for CompileCommandsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        let repo = PathBuf::from(require_str(&args, "repoPath")?);
        let db = compile_db::resolve(&repo).await?;
        Ok(serde_json::to_value(db)?)
    }
}

async fn open_document(client: &ClangdClient, file: &std::path::Path) -> Result<()> {
    let uri = format!("file://{}", file.display());
    let text = tokio::fs::read_to_string(file).await.unwrap_or_default();
    client
        .notify(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": clang_language_id(file),
                    "version": 1,
                    "text": text,
                }
            }),
        )
        .await
}

fn clang_language_id(file: &std::path::Path) -> &'static str {
    match file.extension().and_then(|extension| extension.to_str()) {
        Some("c" | "h") => "c",
        Some("cc" | "cpp" | "cxx" | "hpp" | "hxx" | "hh") => "cpp",
        _ => "cpp",
    }
}

fn position_arg(file: &std::path::Path, line: u32, column: u32) -> Value {
    json!({
        "textDocument": { "uri": format!("file://{}", file.display()) },
        // LSP positions are 0-based.
        "position": { "line": line.saturating_sub(1), "character": column.saturating_sub(1) }
    })
}

#[async_trait]
impl ToolHandler for DefinitionTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        let raw = client
            .request("textDocument/definition", request.params())
            .await?;
        Ok(json!({ "locations": position_locations(&raw) }))
    }
}

#[async_trait]
impl ToolHandler for ReferencesTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        let mut params = request.params();
        params["context"] = json!({ "includeDeclaration": true });
        let raw = client.request("textDocument/references", params).await?;
        Ok(json!({ "locations": range_locations(&raw) }))
    }
}

#[async_trait]
impl ToolHandler for TypeAtTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        let raw = client
            .request("textDocument/hover", request.params())
            .await?;
        Ok(json!({ "hover": raw }))
    }
}

#[async_trait]
impl ToolHandler for AstTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args_with_default_column(&args, 1)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        // clangd-specific extension; not part of LSP standard.
        let raw = client.request("textDocument/ast", request.params()).await?;
        Ok(json!({ "ast": raw }))
    }
}

fn position_locations(raw: &Value) -> Vec<Position> {
    parse_locations(raw)
        .into_iter()
        .map(|(p, l, c)| Position::new(PathBuf::from(p), l).with_column(c))
        .collect()
}

fn range_locations(raw: &Value) -> Vec<Range> {
    parse_locations(raw)
        .into_iter()
        .map(|(p, l, c)| Range {
            start: Position::new(PathBuf::from(&p), l).with_column(c),
            end: Position::new(PathBuf::from(p), l).with_column(c),
        })
        .collect()
}

/// Run `textDocument/prepareCallHierarchy` to get a CallHierarchyItem at
/// the given position; clangd needs this handle before answering
/// `incomingCalls` / `outgoingCalls`.
async fn prepare_call_hierarchy(
    client: &ClangdClient,
    file: &std::path::Path,
    line: u32,
    column: u32,
) -> Result<Value> {
    open_document(client, file).await?;
    let raw = client
        .request(
            "textDocument/prepareCallHierarchy",
            position_arg(file, line, column),
        )
        .await?;
    // clangd returns a `CallHierarchyItem[]`; we forward it verbatim.
    Ok(raw)
}

#[async_trait]
impl ToolHandler for CallersTool {
    async fn call(&self, args: Value) -> Result<Value> {
        call_hierarchy_response(
            &self.handle,
            &args,
            "callHierarchy/incomingCalls",
            "incomingCalls",
        )
        .await
    }
}

#[async_trait]
impl ToolHandler for CalleesTool {
    async fn call(&self, args: Value) -> Result<Value> {
        call_hierarchy_response(
            &self.handle,
            &args,
            "callHierarchy/outgoingCalls",
            "outgoingCalls",
        )
        .await
    }
}

async fn call_hierarchy_response(
    handle: &ClangdHandle,
    args: &Value,
    method: &str,
    field_name: &str,
) -> Result<Value> {
    ensure_clangd()?;
    let request = PositionRequest::from_args(args)?;
    let client = request.client(handle).await?;
    let items =
        prepare_call_hierarchy(&client, &request.file.file, request.line, request.column).await?;
    Ok(json!({ field_name: collect_call_hierarchy_calls(&client, method, &items).await? }))
}

async fn collect_call_hierarchy_calls(
    client: &ClangdClient,
    method: &str,
    items: &Value,
) -> Result<Vec<Value>> {
    let mut calls = Vec::new();
    for item in json_array(items) {
        let response = client.request(method, json!({ "item": item })).await?;
        extend_with_json_array(&mut calls, &response);
    }
    Ok(calls)
}

fn json_array(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or_default()
}

fn extend_with_json_array(target: &mut Vec<Value>, value: &Value) {
    if let Some(items) = value.as_array() {
        target.extend(items.iter().cloned());
    }
}

#[async_trait]
impl ToolHandler for MacroExpandTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = PositionRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file.file).await?;
        // clangd renders the macro expansion in the hover markdown
        // when the cursor is on a macro name. We surface the raw
        // hover plus a best-effort extraction of any code fence whose
        // body contains the expansion.
        let hover = client
            .request("textDocument/hover", request.params())
            .await?;
        let expansion = extract_first_code_fence(&hover);
        Ok(json!({ "hover": hover, "expansion": expansion }))
    }
}

#[async_trait]
impl ToolHandler for SemanticTokensTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = FileRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file).await?;
        let raw = client
            .request("textDocument/semanticTokens/full", request.text_document())
            .await?;
        Ok(json!({ "tokens": raw }))
    }
}

#[async_trait]
impl ToolHandler for DiagnosticsTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let request = FileRequest::from_args(&args)?;
        let client = request.client(&self.handle).await?;
        open_document(&client, &request.file).await?;
        // LSP 3.17 pull diagnostics. clangd implements this when
        // launched with `--enable-config` (default in modern builds).
        let raw = client
            .request("textDocument/diagnostic", request.text_document())
            .await?;
        Ok(json!({ "diagnostics": raw }))
    }
}

/// Pull the first ```...``` code-fence body out of a clangd hover
/// markdown response. Used by `clang.macro_expand` to expose the
/// expanded macro text directly without forcing the caller to parse
/// markdown.
fn extract_first_code_fence(hover: &Value) -> Option<String> {
    let value = hover
        .get("contents")
        .and_then(|c| c.get("value"))
        .or_else(|| hover.get("contents"))
        .and_then(Value::as_str)?;
    let mut lines = value.lines();
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("```") {
            let mut body = Vec::new();
            for inner in lines.by_ref() {
                if inner.trim_start().starts_with("```") {
                    return Some(body.join("\n"));
                }
                body.push(inner.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_includes_all_planned_tools() {
        let r = build_registry();
        for name in [
            "clang.health",
            "clang.compile_commands",
            "clang.definition",
            "clang.references",
            "clang.type_at",
            "clang.ast",
            "clang.callers",
            "clang.callees",
            "clang.macro_expand",
            "clang.semantic_tokens",
            "clang.diagnostics",
        ] {
            assert!(r.contains(name), "missing tool: {name}");
        }
    }

    #[tokio::test]
    async fn definition_tool_reports_backend_unavailable_when_clangd_missing() {
        if which("clangd").is_some() {
            return;
        }
        let tool = DefinitionTool {
            handle: Arc::new(ClangdHandle::default()),
        };
        let err = tool
            .call(json!({"repoPath":"/tmp","file":"x.c","line":1,"column":1}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn callers_reports_backend_unavailable_when_clangd_missing() {
        if which("clangd").is_some() {
            return;
        }
        let tool = CallersTool {
            handle: Arc::new(ClangdHandle::default()),
        };
        let err = tool
            .call(json!({"repoPath":"/tmp","file":"x.c","line":1,"column":1}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn callees_reports_backend_unavailable_when_clangd_missing() {
        if which("clangd").is_some() {
            return;
        }
        let tool = CalleesTool {
            handle: Arc::new(ClangdHandle::default()),
        };
        let err = tool
            .call(json!({"repoPath":"/tmp","file":"x.c","line":1,"column":1}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn diagnostics_reports_backend_unavailable_when_clangd_missing() {
        if which("clangd").is_some() {
            return;
        }
        let tool = DiagnosticsTool {
            handle: Arc::new(ClangdHandle::default()),
        };
        let err = tool
            .call(json!({"repoPath":"/tmp","file":"x.c"}))
            .await
            .unwrap_err();
        assert!(err.to_string().starts_with("BackendUnavailable:"));
    }

    #[tokio::test]
    async fn position_tools_validate_required_arguments_before_opening_files() {
        let handle = Arc::new(ClangdHandle::default());
        for err in [
            DefinitionTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
            ReferencesTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
            TypeAtTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
            AstTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
            MacroExpandTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
        ] {
            assert!(
                err.to_string().starts_with("BackendUnavailable:")
                    || err.to_string().contains("missing required argument")
            );
        }
    }

    #[tokio::test]
    async fn file_tools_validate_required_arguments_before_opening_files() {
        let handle = Arc::new(ClangdHandle::default());
        for err in [
            SemanticTokensTool {
                handle: handle.clone(),
            }
            .call(json!({}))
            .await
            .unwrap_err(),
            DiagnosticsTool { handle }
                .call(json!({}))
                .await
                .unwrap_err(),
        ] {
            assert!(
                err.to_string().starts_with("BackendUnavailable:")
                    || err.to_string().contains("missing required argument")
            );
        }
    }

    #[test]
    fn position_request_requires_column_unless_defaulted() {
        let args = json!({"repoPath":"/repo","file":"src/a.cc","line":7});
        assert!(PositionRequest::from_args(&args).is_err());

        let request = PositionRequest::from_args_with_default_column(&args, 1).unwrap();
        assert_eq!(request.file.repo, PathBuf::from("/repo"));
        assert_eq!(request.file.file, PathBuf::from("/repo/src/a.cc"));
        assert_eq!(request.line, 7);
        assert_eq!(request.column, 1);
    }

    #[test]
    fn lsp_locations_are_projected_to_schema_shapes() {
        let raw = json!([{
            "uri":"file:///repo/a.c",
            "range":{
                "start":{"line":2,"character":4},
                "end":{"line":2,"character":9}
            }
        }]);

        let positions = position_locations(&raw);
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0].line, 3);
        assert_eq!(positions[0].column, Some(5));

        let ranges = range_locations(&raw);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start.line, 3);
        assert_eq!(ranges[0].end.column, Some(5));
    }

    #[test]
    fn call_hierarchy_response_helpers_ignore_non_arrays() {
        let mut calls = vec![json!({"name":"existing"})];
        extend_with_json_array(&mut calls, &json!({"not":"array"}));
        assert_eq!(calls.len(), 1);

        extend_with_json_array(&mut calls, &json!([{"name":"next"}]));
        assert_eq!(
            calls,
            vec![json!({"name":"existing"}), json!({"name":"next"})]
        );
        assert!(json_array(&json!({"not":"array"})).is_empty());
    }

    #[test]
    fn clang_language_id_maps_c_and_cpp_extensions() {
        assert_eq!(clang_language_id(std::path::Path::new("main.c")), "c");
        assert_eq!(clang_language_id(std::path::Path::new("main.h")), "c");
        assert_eq!(clang_language_id(std::path::Path::new("main.cpp")), "cpp");
        assert_eq!(clang_language_id(std::path::Path::new("main.hh")), "cpp");
        assert_eq!(clang_language_id(std::path::Path::new("README")), "cpp");
    }

    #[test]
    fn extract_first_code_fence_handles_clangd_markdown_hover() {
        // Realistic clangd hover for a macro: wraps the expansion in a
        // ```c ... ``` block.
        let hover = json!({
            "contents": {
                "kind": "markdown",
                "value": "Macro `MAX(x, y)`\n\n```c\n((x) > (y) ? (x) : (y))\n```\n"
            }
        });
        let extracted = extract_first_code_fence(&hover);
        assert_eq!(extracted.as_deref(), Some("((x) > (y) ? (x) : (y))"));
    }

    #[test]
    fn extract_first_code_fence_returns_none_when_no_fence() {
        let hover = json!({
            "contents": {"kind": "markdown", "value": "no code here"}
        });
        assert!(extract_first_code_fence(&hover).is_none());
    }

    #[test]
    fn extract_first_code_fence_handles_plain_string_contents() {
        let hover = json!({ "contents": "```\nplain\n```" });
        assert_eq!(extract_first_code_fence(&hover).as_deref(), Some("plain"));
    }
}
