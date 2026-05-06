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
        if let Some((existing, client)) = guard.as_ref() {
            if existing == &canonical {
                return Ok(client.clone());
            }
            // Different repo — best-effort shutdown of the prior client.
            let _ = client.shutdown().await;
        }
        let client = Arc::new(ClangdClient::spawn(&canonical).await?);
        client.initialize(&canonical).await?;
        *guard = Some((canonical, client.clone()));
        Ok(client)
    }
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
        // Stubs for the rest of the planned surface — return a structured
        // "not yet implemented" so MCP clients can detect them.
        .register(
            stub_descriptor("clang.callers", "Incoming-call hierarchy at a symbol (planned)."),
            NotYetImplemented("clang.callers"),
        )
        .register(
            stub_descriptor("clang.callees", "Outgoing-call hierarchy at a symbol (planned)."),
            NotYetImplemented("clang.callees"),
        )
        .register(
            stub_descriptor("clang.macro_expand", "Macro expansion at a position (planned)."),
            NotYetImplemented("clang.macro_expand"),
        )
        .register(
            stub_descriptor("clang.semantic_tokens", "Semantic tokens for a file (planned)."),
            NotYetImplemented("clang.semantic_tokens"),
        )
        .register(
            stub_descriptor("clang.diagnostics", "Diagnostics for a file (planned)."),
            NotYetImplemented("clang.diagnostics"),
        )
}

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
    let language_id = match file.extension().and_then(|e| e.to_str()) {
        Some("c") => "c",
        Some("h") => "c",
        Some("cc" | "cpp" | "cxx" | "hpp" | "hxx" | "hh") => "cpp",
        _ => "cpp",
    };
    client
        .notify(
            "textDocument/didOpen",
            json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": language_id,
                    "version": 1,
                    "text": text,
                }
            }),
        )
        .await
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
        let repo = PathBuf::from(require_str(&args, "repoPath")?);
        let file = repo.join(require_str(&args, "file")?);
        let line = require_u32(&args, "line")?;
        let column = require_u32(&args, "column")?;
        let client = self.handle.for_repo(&repo).await?;
        open_document(&client, &file).await?;
        let raw = client
            .request("textDocument/definition", position_arg(&file, line, column))
            .await?;
        let locations: Vec<Position> = parse_locations(&raw)
            .into_iter()
            .map(|(p, l, c)| Position::new(PathBuf::from(p), l).with_column(c))
            .collect();
        Ok(json!({ "locations": locations }))
    }
}

#[async_trait]
impl ToolHandler for ReferencesTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let repo = PathBuf::from(require_str(&args, "repoPath")?);
        let file = repo.join(require_str(&args, "file")?);
        let line = require_u32(&args, "line")?;
        let column = require_u32(&args, "column")?;
        let client = self.handle.for_repo(&repo).await?;
        open_document(&client, &file).await?;
        let mut params = position_arg(&file, line, column);
        params["context"] = json!({ "includeDeclaration": true });
        let raw = client.request("textDocument/references", params).await?;
        let locations: Vec<Range> = parse_locations(&raw)
            .into_iter()
            .map(|(p, l, c)| Range {
                start: Position::new(PathBuf::from(&p), l).with_column(c),
                end: Position::new(PathBuf::from(p), l).with_column(c),
            })
            .collect();
        Ok(json!({ "locations": locations }))
    }
}

#[async_trait]
impl ToolHandler for TypeAtTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let repo = PathBuf::from(require_str(&args, "repoPath")?);
        let file = repo.join(require_str(&args, "file")?);
        let line = require_u32(&args, "line")?;
        let column = require_u32(&args, "column")?;
        let client = self.handle.for_repo(&repo).await?;
        open_document(&client, &file).await?;
        let raw = client
            .request("textDocument/hover", position_arg(&file, line, column))
            .await?;
        Ok(json!({ "hover": raw }))
    }
}

#[async_trait]
impl ToolHandler for AstTool {
    async fn call(&self, args: Value) -> Result<Value> {
        ensure_clangd()?;
        let repo = PathBuf::from(require_str(&args, "repoPath")?);
        let file = repo.join(require_str(&args, "file")?);
        let line = require_u32(&args, "line")?;
        let column = args.get("column").and_then(Value::as_u64).unwrap_or(1) as u32;
        let client = self.handle.for_repo(&repo).await?;
        open_document(&client, &file).await?;
        // clangd-specific extension; not part of LSP standard.
        let raw = client
            .request("textDocument/ast", position_arg(&file, line, column))
            .await?;
        Ok(json!({ "ast": raw }))
    }
}

#[async_trait]
impl ToolHandler for NotYetImplemented {
    async fn call(&self, _args: Value) -> Result<Value> {
        anyhow::bail!(
            "NotYetImplemented: tool `{}` is part of the planned clang MCP surface but is not yet wired. See plan in /root/.claude/plans/can-you-plan-how-concurrent-acorn.md",
            self.0
        )
    }
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
    async fn stub_tools_return_not_yet_implemented() {
        let tool = NotYetImplemented("clang.callers");
        let err = tool.call(json!({})).await.unwrap_err();
        assert!(err.to_string().starts_with("NotYetImplemented:"));
        assert!(err.to_string().contains("clang.callers"));
    }
}
