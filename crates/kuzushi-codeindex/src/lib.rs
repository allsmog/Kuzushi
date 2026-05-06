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

    fn client_mut(&mut self, backend: Backend) -> Option<&mut McpClient> {
        match backend {
            Backend::Gtags => self.gtags.as_mut(),
            Backend::Clang => self.clang.as_mut(),
            Backend::Joern => self.joern.as_mut(),
        }
    }
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
}
