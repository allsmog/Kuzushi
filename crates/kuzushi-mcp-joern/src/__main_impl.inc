use std::env;

use anyhow::Result;
use kuzushi_mcp_common::{serve_stdio, ServerInfo};

#[path = "queries/implementation.inc"]
mod queries;
#[path = "server/implementation.inc"]
mod server;
#[path = "tools/implementation.inc"]
mod tools;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().any(|a| a == "--health") {
        let summary = tools::health_summary().await;
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    let info = ServerInfo::new("kuzushi-mcp-joern", PKG_VERSION);
    let registry = tools::build_registry();
    serve_stdio(info, registry).await
}
