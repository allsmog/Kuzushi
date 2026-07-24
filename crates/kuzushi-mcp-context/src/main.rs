use anyhow::Result;
use kuzushi_mcp_common::{exit_after_standalone_health_if_requested, serve_stdio, ServerInfo};

mod tools;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let info = ServerInfo::new("kuzushi-mcp-context", PKG_VERSION);
    exit_after_standalone_health_if_requested(&info)?;
    let registry = tools::build_registry()?;
    serve_stdio(info, registry).await
}
