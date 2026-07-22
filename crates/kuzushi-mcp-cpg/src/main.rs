use anyhow::Result;
use kuzushi_mcp_common::{serve_stdio, ServerInfo};

mod engine;
mod tools;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|a| a == "--health") {
        println!(
            "{}",
            serde_json::to_string_pretty(&tools::health_summary())?
        );
        return Ok(());
    }
    let info = ServerInfo::new("kuzushi-mcp-cpg", PKG_VERSION);
    let registry = tools::build_registry();
    serve_stdio(info, registry).await
}
