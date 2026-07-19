use anyhow::Result;
use kuzushi_mcp_common::{exit_after_standalone_health_if_requested, serve_stdio, ServerInfo};

mod database_identity;
mod tools;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let info = ServerInfo::new("kuzushi-mcp-codeql", PKG_VERSION);
    exit_after_standalone_health_if_requested(&info)?;
    let (runtime, registry) = tools::build_runtime_and_registry()?;
    // Background pack-cache pre-warm. KUZUSHI_CODEQL_PREWARM=1 enables it;
    // by default we leave it off so server startup does not wait for CodeQL. An
    // owned Tokio task runs `codeql query compile` for the common CWE
    // folders so the agent's first `flows_for_cwe` call avoids a cold pack
    // compile. Database content authentication still runs on that call.
    let prewarm = if std::env::var("KUZUSHI_CODEQL_PREWARM")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        let runtime = std::sync::Arc::clone(&runtime);
        Some(tokio::spawn(async move {
            tools::spawn_prewarm(&runtime).await;
        }))
    } else {
        None
    };
    let served = serve_stdio(info, registry).await;
    runtime.cancel();
    if let Some(prewarm) = prewarm {
        let _ = prewarm.await;
    }
    drop(runtime);
    served
}
