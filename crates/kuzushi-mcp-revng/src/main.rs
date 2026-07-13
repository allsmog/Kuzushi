use anyhow::Result;
use kuzushi_mcp_common::{serve_stdio, ServerInfo};
use std::env;

mod tools;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    if env::args().any(|a| a == "--health") {
        let summary = tools::health_summary().await;
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    let info = ServerInfo::new("kuzushi-mcp-revng", PKG_VERSION);
    let registry = tools::build_registry()?;
    serve_stdio(info, registry).await
}
