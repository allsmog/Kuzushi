use anyhow::Result;
use kuzushi_mcp_common::{serve_stdio, ServerInfo};

mod tools;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let info = ServerInfo::new("kuzushi-mcp-entry-points", PKG_VERSION);
    let registry = tools::build_registry();
    serve_stdio(info, registry).await
}
