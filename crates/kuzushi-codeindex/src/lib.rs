//! Unified code-index facade.
//!
//! Other Kuzushi modules call into this crate without caring which MCP
//! backend (joern, clang, gtags) actually answered the query. The facade:
//!
//! 1. Spawns each MCP server as a child process on demand.
//! 2. Speaks JSON-RPC client to it over stdio.
//! 3. Routes high-level queries to the best-available backend per the
//!    routing table in [`router`].
//! 4. Exposes a single [`IndexFacade`] surface so consumers (systems-hunt,
//!    future verify, future taint) stay backend-agnostic.

pub mod client;
pub mod router;

pub use client::{ClientError, McpClient};
pub use router::{Backend, BackendCapability, Query, RoutingTable};

use std::path::Path;

use anyhow::Result;
use kuzushi_mcp_common::schema::Symbol;
use serde_json::Value;

/// Top-level facade. Holds at most one running MCP client per backend.
#[derive(Default)]
pub struct IndexFacade {
    pub gtags: Option<McpClient>,
    pub clang: Option<McpClient>,
    pub joern: Option<McpClient>,
    routing: RoutingTable,
}

impl IndexFacade {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a facade that auto-spawns each backend it can find on PATH.
    /// Backends whose binaries are missing are simply omitted from the
    /// routing table — every query degrades gracefully to whatever
    /// remains.
    pub async fn with_available_backends() -> Self {
        let mut facade = Self::new();
        if let Ok(client) = McpClient::spawn(Backend::Gtags.binary_name()).await {
            facade.gtags = Some(client);
        }
        if let Ok(client) = McpClient::spawn(Backend::Clang.binary_name()).await {
            facade.clang = Some(client);
        }
        if let Ok(client) = McpClient::spawn(Backend::Joern.binary_name()).await {
            facade.joern = Some(client);
        }
        facade
    }

    /// Returns which backends are live for this facade.
    pub fn live_backends(&self) -> Vec<Backend> {
        let mut out = Vec::new();
        if self.gtags.is_some() {
            out.push(Backend::Gtags);
        }
        if self.clang.is_some() {
            out.push(Backend::Clang);
        }
        if self.joern.is_some() {
            out.push(Backend::Joern);
        }
        out
    }

    /// Find symbol definitions. Routes per [`RoutingTable`].
    pub async fn definitions(&mut self, symbol: &str, repo: &Path) -> Result<Vec<Symbol>> {
        for backend in self.routing.order_for(Query::Definitions) {
            let Some(client) = self.client_mut(backend) else {
                continue;
            };
            let tool = match backend {
                Backend::Clang => "clang.definition",
                Backend::Gtags => "gtags.definitions",
                Backend::Joern => "joern.query",
            };
            let args = match backend {
                Backend::Gtags => serde_json::json!({
                    "symbol": symbol,
                    "repoPath": repo,
                }),
                Backend::Clang => serde_json::json!({
                    // Without a (file, line, column) we can't ask clangd
                    // for a definition; for the symbol-by-name route we
                    // fall through to gtags.
                    "skip": true,
                }),
                Backend::Joern => serde_json::json!({
                    "scala": format!("cpg.method.name(\"{}\").l", symbol.replace('"', "\\\""))
                }),
            };
            if let Some(skip) = args.get("skip") {
                if skip == &serde_json::Value::Bool(true) {
                    continue;
                }
            }
            match client.call_tool(tool, args).await {
                Ok(value) => {
                    if let Some(matches) = value.get("matches") {
                        if let Ok(syms) = serde_json::from_value::<Vec<Symbol>>(matches.clone()) {
                            return Ok(syms);
                        }
                    }
                    return Ok(Vec::new());
                }
                Err(err) => {
                    eprintln!(
                        "[codeindex] {} backend failed for definitions({symbol}): {err}",
                        backend.binary_name()
                    );
                    continue;
                }
            }
        }
        anyhow::bail!("no backend was able to answer definitions({symbol})")
    }

    /// Find symbol references (callers, usages). Routes per
    /// [`RoutingTable`].
    pub async fn references(&mut self, symbol: &str, repo: &Path) -> Result<Vec<Symbol>> {
        for backend in self.routing.order_for(Query::References) {
            let Some(client) = self.client_mut(backend) else {
                continue;
            };
            // Same shape as definitions for gtags; clang/joern need
            // location/Scala respectively.
            if backend != Backend::Gtags {
                continue;
            }
            let args = serde_json::json!({
                "symbol": symbol,
                "repoPath": repo,
            });
            match client.call_tool("gtags.references", args).await {
                Ok(value) => {
                    if let Some(matches) = value.get("matches") {
                        if let Ok(syms) = serde_json::from_value::<Vec<Symbol>>(matches.clone()) {
                            return Ok(syms);
                        }
                    }
                    return Ok(Vec::new());
                }
                Err(err) => {
                    eprintln!(
                        "[codeindex] {} backend failed for references({symbol}): {err}",
                        backend.binary_name()
                    );
                    continue;
                }
            }
        }
        anyhow::bail!("no backend was able to answer references({symbol})")
    }

    /// Methods that call the named function. Routes per [`RoutingTable`].
    /// Tries clang first when (file, line, column) is supplied; otherwise
    /// falls through to joern's name-based query.
    pub async fn callers_of(
        &mut self,
        symbol: &str,
        position: Option<&FilePosition>,
    ) -> Result<Value> {
        for backend in self.routing.order_for(Query::CallersOfFunction) {
            let Some(client) = self.client_mut(backend) else {
                continue;
            };
            let (tool, args) = match (backend, position) {
                (Backend::Clang, Some(pos)) => (
                    "clang.callers",
                    serde_json::json!({
                        "repoPath": pos.repo,
                        "file": pos.file,
                        "line": pos.line,
                        "column": pos.column,
                    }),
                ),
                (Backend::Joern, _) => ("joern.callers_of", serde_json::json!({ "fn": symbol })),
                // gtags and clang-without-position can't answer a
                // function-callers query usefully; skip.
                _ => continue,
            };
            match client.call_tool(tool, args).await {
                Ok(value) => return Ok(value),
                Err(err) => {
                    eprintln!(
                        "[codeindex] {} backend failed for callers_of({symbol}): {err}",
                        backend.binary_name()
                    );
                    continue;
                }
            }
        }
        anyhow::bail!("no backend was able to answer callers_of({symbol})")
    }

    /// Methods called by the named function. Routes per [`RoutingTable`].
    pub async fn callees_of(
        &mut self,
        symbol: &str,
        position: Option<&FilePosition>,
    ) -> Result<Value> {
        for backend in self.routing.order_for(Query::CalleesOfFunction) {
            let Some(client) = self.client_mut(backend) else {
                continue;
            };
            let (tool, args) = match (backend, position) {
                (Backend::Joern, _) => ("joern.callees_of", serde_json::json!({ "fn": symbol })),
                (Backend::Clang, Some(pos)) => (
                    "clang.callees",
                    serde_json::json!({
                        "repoPath": pos.repo,
                        "file": pos.file,
                        "line": pos.line,
                        "column": pos.column,
                    }),
                ),
                _ => continue,
            };
            match client.call_tool(tool, args).await {
                Ok(value) => return Ok(value),
                Err(err) => {
                    eprintln!(
                        "[codeindex] {} backend failed for callees_of({symbol}): {err}",
                        backend.binary_name()
                    );
                    continue;
                }
            }
        }
        anyhow::bail!("no backend was able to answer callees_of({symbol})")
    }

    /// Taint paths from a source pattern to a sink pattern. joern only;
    /// no fallback because gtags and clang lack the dataflow primitives.
    pub async fn taint_paths(
        &mut self,
        source: &str,
        sink: &str,
        max_paths: Option<usize>,
    ) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Joern) else {
            anyhow::bail!(
                "BackendUnavailable: taint_paths requires joern; install via https://docs.joern.io/installation"
            );
        };
        let mut args = serde_json::json!({
            "source": source,
            "sink": sink,
        });
        if let Some(n) = max_paths {
            args["maxPaths"] = serde_json::json!(n);
        }
        client.call_tool("joern.taint_paths", args).await
    }

    /// Locate `unsafe { ... }` regions, optionally constrained to a file.
    /// joern Rust frontend.
    pub async fn unsafe_blocks(&mut self, file: Option<&str>) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Joern) else {
            anyhow::bail!(
                "BackendUnavailable: unsafe_blocks requires joern; install via https://docs.joern.io/installation"
            );
        };
        let mut args = serde_json::json!({});
        if let Some(f) = file {
            args["file"] = serde_json::json!(f);
        }
        client.call_tool("joern.unsafe_blocks", args).await
    }

    /// Locate FFI boundaries (extern, JNI, dlsym/dlopen). joern only.
    pub async fn ffi_boundaries(&mut self) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Joern) else {
            anyhow::bail!(
                "BackendUnavailable: ffi_boundaries requires joern; install via https://docs.joern.io/installation"
            );
        };
        client
            .call_tool("joern.ffi_boundaries", serde_json::json!({}))
            .await
    }

    /// Type information at a position. clang only — needs type-and-macro
    /// awareness from clangd.
    pub async fn type_at(&mut self, position: &FilePosition) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Clang) else {
            anyhow::bail!(
                "BackendUnavailable: type_at requires clangd; install LLVM (`apt install clangd` / `brew install llvm`)"
            );
        };
        client
            .call_tool(
                "clang.type_at",
                serde_json::json!({
                    "repoPath": position.repo,
                    "file": position.file,
                    "line": position.line,
                    "column": position.column,
                }),
            )
            .await
    }

    /// AST subtree at a position via clangd's `textDocument/ast` extension.
    pub async fn ast(&mut self, position: &FilePosition) -> Result<Value> {
        let Some(client) = self.client_mut(Backend::Clang) else {
            anyhow::bail!(
                "BackendUnavailable: ast requires clangd; install LLVM (`apt install clangd` / `brew install llvm`)"
            );
        };
        client
            .call_tool(
                "clang.ast",
                serde_json::json!({
                    "repoPath": position.repo,
                    "file": position.file,
                    "line": position.line,
                    "column": position.column,
                }),
            )
            .await
    }

    fn client_mut(&mut self, backend: Backend) -> Option<&mut McpClient> {
        match backend {
            Backend::Gtags => self.gtags.as_mut(),
            Backend::Clang => self.clang.as_mut(),
            Backend::Joern => self.joern.as_mut(),
        }
    }
}

/// Convenience input for the position-aware facade methods. Accepts a
/// repo path + file (relative to the repo) + 1-based line/column.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilePosition {
    pub repo: std::path::PathBuf,
    pub file: String,
    pub line: u32,
    pub column: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_facade_reports_no_live_backends() {
        let facade = IndexFacade::new();
        assert!(facade.live_backends().is_empty());
    }

    #[tokio::test]
    async fn definitions_with_no_backends_errors_actionably() {
        let mut facade = IndexFacade::new();
        let err = facade
            .definitions("foo", Path::new("/tmp"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no backend"));
    }

    #[tokio::test]
    async fn callers_of_errors_when_no_backend_live() {
        let mut facade = IndexFacade::new();
        let err = facade.callers_of("foo", None).await.unwrap_err();
        assert!(err.to_string().contains("no backend"));
    }

    #[tokio::test]
    async fn taint_paths_reports_backend_unavailable_without_joern() {
        let mut facade = IndexFacade::new();
        let err = facade
            .taint_paths("argv", "system", None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("BackendUnavailable"));
        assert!(err.to_string().contains("joern"));
    }

    #[tokio::test]
    async fn unsafe_blocks_reports_backend_unavailable_without_joern() {
        let mut facade = IndexFacade::new();
        let err = facade.unsafe_blocks(None).await.unwrap_err();
        assert!(err.to_string().contains("joern"));
    }

    #[tokio::test]
    async fn ffi_boundaries_reports_backend_unavailable_without_joern() {
        let mut facade = IndexFacade::new();
        let err = facade.ffi_boundaries().await.unwrap_err();
        assert!(err.to_string().contains("joern"));
    }

    #[tokio::test]
    async fn type_at_reports_backend_unavailable_without_clang() {
        let mut facade = IndexFacade::new();
        let pos = FilePosition {
            repo: std::path::PathBuf::from("/tmp"),
            file: "x.c".to_string(),
            line: 1,
            column: 1,
        };
        let err = facade.type_at(&pos).await.unwrap_err();
        assert!(err.to_string().contains("clangd"));
    }

    #[tokio::test]
    async fn ast_reports_backend_unavailable_without_clang() {
        let mut facade = IndexFacade::new();
        let pos = FilePosition {
            repo: std::path::PathBuf::from("/tmp"),
            file: "x.c".to_string(),
            line: 1,
            column: 1,
        };
        let err = facade.ast(&pos).await.unwrap_err();
        assert!(err.to_string().contains("clangd"));
    }
}
