use anyhow::Result;
use kuzushi_mcp_common::{exit_after_standalone_health_if_requested, serve_stdio, ServerInfo};

mod database_identity;
mod tools;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let info = ServerInfo::new("kuzushi-mcp-codeql", PKG_VERSION);
    exit_after_standalone_health_if_requested(&info)?;
    let registry = tools::build_registry()?;
    // Background pack-cache pre-warm. KUZUSHI_CODEQL_PREWARM=1 enables it;
    // by default we leave it off so the MCP server starts instantly. A
    // detached tokio task runs `codeql query compile` for the common CWE
    // folders so the agent's first `flows_for_cwe` call is a cache hit
    // instead of a 60s cold compile.
    if std::env::var("KUZUSHI_CODEQL_PREWARM")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        tokio::spawn(async {
            tools::spawn_prewarm().await;
        });
    }
    serve_stdio(info, registry).await
}
